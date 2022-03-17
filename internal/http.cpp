#include "http.h"

#include "acme-exception.h"

#include <curl/curl.h>

#include <algorithm>
#include <cstring>
#include <unordered_map>

using namespace std;

using namespace acme_lw;

namespace
{

/** Handles automatic CURL initialization & teardown.
 */
class CURLGlobalInit {
private:
    inline CURLGlobalInit() 
    {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    inline ~CURLGlobalInit() 
    {
        curl_global_cleanup();
    }

    static CURLGlobalInit curlGlobalInit_;
}

CURLGlobalInit::curlGlobalInit_;


struct Ptr
{
    Ptr()
        : curl_(curl_easy_init())
    {
        if (!curl_)
        {
            throw acme_lw::AcmeException("Error initializing curl");
        }
    }

    ~Ptr()
    {
        curl_easy_cleanup(curl_);
    }

    CURL * operator * () const
    {
        return curl_;
    }

private:
    CURL * curl_;
};

std::string toLowercase(const std::string &str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c){ return std::tolower(c); });
    return result;
}

size_t headerCallback(void * buffer, size_t size, size_t nmemb, void * h)
{
    // header -> 'key': 'value'
    unordered_map<string, string>& headers = *reinterpret_cast<unordered_map<string, string> *>(h);

    size_t byteCount = size * nmemb;
    string line(reinterpret_cast<const char *>(buffer), byteCount);

    // Header looks like 'X: Y'. This gets the 'Y'
    auto pos = line.find(": ");
    if (pos != string::npos)
    {
        // Headers are case insensitive, so we convert everything to lowercase for easy lookup
        string name = toLowercase(line.substr(0,pos));
        string value = line.substr(pos + 2, byteCount - pos - 2);

        // Trim trailing whitespace
        headers.emplace(name, value.erase(value.find_last_not_of(" \n\r") + 1));
    }

    return byteCount;
}

size_t dataCallback(void * buffer, size_t size, size_t nmemb, void * response)
{
    vector<char>& v = *reinterpret_cast<vector<char> *>(response);

    size_t byteCount = size * nmemb;

    size_t initSize = v.size();
    v.resize(initSize + byteCount);
    memcpy(&v[initSize], buffer, byteCount);

    return byteCount;
}

string getCurlError(const string& s, CURLcode c)
{
    return s + ": " + curl_easy_strerror(c);
}

}

namespace acme_lw_internal
{

void doCurl(Ptr& curl, const string& url, const vector<char>& response)
{
    auto res = curl_easy_perform(*curl);
    if (res != CURLE_OK)
    {
        throw AcmeException(getCurlError("Failure contacting "s + url +" to read a header.", res));
    }

    long responseCode;
    curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &responseCode);
    if (responseCode / 100 != 2)
    {
        // If it's not a 2xx response code, throw.
        std::string responseString = string(&response.front(), response.size());
        throw AcmeException("Response code of "s + to_string(responseCode) + " contacting " + url + 
                            " with response of:\n" + responseString, responseString);
    }
}

string getHeader(const string& url, const string& headerKey)
{
    Ptr curl;
    curl_easy_setopt(*curl, CURLOPT_URL, url.c_str());

    // Does a HEAD request
    curl_easy_setopt(*curl, CURLOPT_NOBODY, 1);

    curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, &headerCallback);

    unordered_map<string, string> headers;
    curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &headers);

    // There will be no response (probably). We just pass this
    // for error handling
    vector<char> response;
    doCurl(curl, url, response);
    
    return headers[toLowercase(headerKey)];
}

Response doPost(const string& url, const string& postBody, const char * headerKey)
{
    Response response;

    Ptr curl;

    curl_easy_setopt(*curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(*curl, CURLOPT_POST, 1);
    curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, postBody.c_str());
    curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, dataCallback);
    curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &response.response_);

    curl_slist h = { const_cast<char *>("Content-Type: application/jose+json"), nullptr };
    curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, &h);

    unordered_map<string, string> headers;
    if (headerKey)
    {
        curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, &headerCallback);

        curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &headers);
    }

    doCurl(curl, url, response.response_);
    
    if(headerKey) 
    {
        response.headerValue_ = headers[toLowercase(headerKey)];
    }
    response.replayNonce_ = headers["replay-nonce"];
    
    return response;
}

vector<char> doGet(const string& url)
{
    vector<char> response;

    Ptr curl;

    curl_easy_setopt(*curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, dataCallback);
    curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &response);

    doCurl(curl, url, response);

    return response;
}

}

