#pragma comment(lib, "wininet")
#pragma comment(lib, "crypt32")

#include <iostream>
#include <set>
#include <windows.h>
#include <wininet.h>
#include "json11.hpp"

BOOL GetStringFromJSON(LPCSTR lpszJson, LPCSTR lpszKey, LPSTR lpszValue, int nSizeValue)
{
	std::string src(lpszJson);
	std::string err;
	json11::Json v = json11::Json::parse(src, err);
	if (err.size()) return FALSE;
	lpszValue[0] = 0;
	strcpy_s(lpszValue, nSizeValue, v[lpszKey].string_value().c_str());
	return strlen(lpszValue) > 0;
}

BOOL String2Base64(LPWSTR lpszBase64String, DWORD dwSize)
{
	BOOL bReturn = FALSE;
	DWORD dwLength = WideCharToMultiByte(CP_ACP, 0, lpszBase64String, -1, 0, 0, 0, 0);
	LPSTR lpszStringA = (LPSTR)GlobalAlloc(GPTR, dwLength * sizeof(char));
	WideCharToMultiByte(CP_ACP, 0, lpszBase64String, -1, lpszStringA, dwLength, 0, 0);
	DWORD dwResult = 0;
	if (CryptBinaryToStringW((LPBYTE)lpszStringA, dwLength - 1, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, 0, &dwResult))
	{
		if (dwResult <= dwSize && CryptBinaryToStringW((LPBYTE)lpszStringA, dwLength - 1, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, lpszBase64String, &dwResult))
		{
			bReturn = TRUE;
		}
	}
	GlobalFree(lpszStringA);
	return bReturn;
}

BOOL GetTwitterBearerToken(IN LPCWSTR lpszConsumerKey, IN LPCWSTR lpszConsumerSecret, OUT LPWSTR lpszBearerToken, IN DWORD dwSize)
{
	HINTERNET hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternet == NULL)
	{
		return FALSE;
	}
	HINTERNET hSession = InternetConnectW(hInternet, L"api.twitter.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hSession == NULL)
	{
		InternetCloseHandle(hInternet);
		return FALSE;
	}
	HINTERNET hRequest = HttpOpenRequestW(hSession, L"POST", L"/oauth2/token", NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
	if (hRequest == NULL)
	{
		InternetCloseHandle(hSession);
		InternetCloseHandle(hInternet);
		return FALSE;
	}
	WCHAR credential[1024];
	wsprintfW(credential, L"%s:%s", lpszConsumerKey, lpszConsumerSecret);
	String2Base64(credential, sizeof(credential));
	WCHAR header[1024];
	wsprintfW(header, L"Authorization: Basic %s\r\nContent-Type: application/x-www-form-urlencoded;charset=UTF-8", credential);
	CHAR param[] = "grant_type=client_credentials";
	if (!HttpSendRequestW(hRequest, header, (DWORD)wcslen(header), param, (DWORD)strlen(param)))
	{
		InternetCloseHandle(hRequest);
		InternetCloseHandle(hSession);
		InternetCloseHandle(hInternet);
		return FALSE;
	}
	BOOL bResult = FALSE;
	WCHAR szBuffer[256] = { 0 };
	DWORD dwBufferSize = _countof(szBuffer);
	HttpQueryInfoW(hRequest, HTTP_QUERY_CONTENT_LENGTH, szBuffer, &dwBufferSize, NULL);
	DWORD dwContentLength = _wtol(szBuffer);
	LPBYTE lpByte = (LPBYTE)GlobalAlloc(0, dwContentLength + 1);
	if (lpByte != NULL) {
		DWORD dwReadSize;
		InternetReadFile(hRequest, lpByte, dwContentLength, &dwReadSize);
		lpByte[dwReadSize] = 0;
		CHAR szAccessToken[256];
		if (GetStringFromJSON((LPCSTR)lpByte, "access_token", szAccessToken, _countof(szAccessToken)))
		{
			DWORD nLength = MultiByteToWideChar(CP_THREAD_ACP, 0, szAccessToken, -1, 0, 0);
			if (nLength <= dwSize)
			{
				MultiByteToWideChar(CP_THREAD_ACP, 0, szAccessToken, -1, lpszBearerToken, nLength);
				bResult = TRUE;
			}
		}
		GlobalFree(lpByte);
	}
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hSession);
	InternetCloseHandle(hInternet);
	return bResult;
}

BOOL GetFollowWithoutFollower(LPCWSTR lpszBearerToken, LPCWSTR lpszTwitterID, LPCWSTR lpszKind, std::set<LONGLONG>* set)
{
	HINTERNET hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternet == NULL)
	{
		return FALSE;
	}
	HINTERNET hSession = InternetConnectW(hInternet, L"api.twitter.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hSession == NULL)
	{
		InternetCloseHandle(hInternet);
		return FALSE;
	}
	WCHAR szPreviousCursor[32] = { 0 };
	WCHAR szNextCursor[32] = { 0 };
	for (;;)
	{
		WCHAR szURL[1024];
		wcscpy_s(szURL, _countof(szURL), L"1.1/");
		wcscat_s(szURL, _countof(szURL), lpszKind);
		wcscat_s(szURL, _countof(szURL), L"/ids.json?screen_name=");
		wcscat_s(szURL, _countof(szURL), lpszTwitterID);
		wcscat_s(szURL, _countof(szURL), L"&stringify_ids=true");
		if (szNextCursor[0])
		{
			wcscat_s(szURL, _countof(szURL), L"&cursor=");
			wcscat_s(szURL, _countof(szURL), szNextCursor);
		}
		HINTERNET hRequest = HttpOpenRequestW(hSession, L"GET", szURL, NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
		if (hRequest == NULL)
		{
			InternetCloseHandle(hSession);
			InternetCloseHandle(hInternet);
			return FALSE;
		}
		WCHAR header[1024];
		wsprintfW(header, L"Authorization: Bearer %s", lpszBearerToken);
		if (!HttpSendRequestW(hRequest, header, (DWORD)wcslen(header), 0, 0))
		{
			InternetCloseHandle(hRequest);
			InternetCloseHandle(hSession);
			InternetCloseHandle(hInternet);
			return FALSE;
		}
		WCHAR szBuffer[256] = { 0 };
		DWORD dwBufferSize = _countof(szBuffer);
		HttpQueryInfoW(hRequest, HTTP_QUERY_CONTENT_LENGTH, szBuffer, &dwBufferSize, NULL);
		DWORD dwContentLength = _wtol(szBuffer);
		LPBYTE lpByte = (LPBYTE)GlobalAlloc(0, dwContentLength + 1);
		if (lpByte == 0)
		{
			InternetCloseHandle(hRequest);
			InternetCloseHandle(hSession);
			InternetCloseHandle(hInternet);
			return FALSE;
		}
		DWORD dwReadSize;
		InternetReadFile(hRequest, lpByte, dwContentLength, &dwReadSize);
		lpByte[dwReadSize] = 0;
		{
			std::string src((LPSTR)lpByte);
			std::string parseerror;
			json11::Json v = json11::Json::parse(src, parseerror);
			std::string twittererror = v["errors"][0]["message"].string_value();
			if (parseerror.size() || twittererror.size())
			{
				std::cout << twittererror << std::endl;
				GlobalFree(lpByte);
				InternetCloseHandle(hRequest);
				InternetCloseHandle(hSession);
				InternetCloseHandle(hInternet);
				return FALSE;
			}
			{
				{
					const DWORD dwSize = MultiByteToWideChar(CP_UTF8, 0, v["next_cursor_str"].string_value().c_str(), -1, 0, 0);
					MultiByteToWideChar(CP_UTF8, 0, v["next_cursor_str"].string_value().c_str(), -1, szNextCursor, dwSize);
					if (wcscmp(szPreviousCursor, szNextCursor) == 0 || lstrcmp(szPreviousCursor, L"0") == 0)
					{
						GlobalFree(lpByte);
						InternetCloseHandle(hRequest);
						break;
					}
					else
					{
						wcscpy_s(szPreviousCursor, szNextCursor);
					}
				}
				for (auto t : v["ids"].array_items())
				{
					int nSize = (int)t.string_value().size() + 1;
					DWORD dwSize = MultiByteToWideChar(CP_UTF8, 0, t.string_value().c_str(), nSize, 0, 0);
					LPWSTR lpszContentW = (LPWSTR)GlobalAlloc(0, dwSize * sizeof(WCHAR));
					MultiByteToWideChar(CP_UTF8, 0, t.string_value().c_str(), nSize, lpszContentW, dwSize);
					{
						LPWSTR next = NULL;
						LPWSTR lpszLine = wcstok_s(lpszContentW, L"\n", &next);
						while (lpszLine)
						{
							errno = 0;
							LONGLONG userid = wcstoll(lpszLine, 0, 0);
							if (errno == ERANGE) {
								errno = 0;
								std::wcout << "User ID has exceeded the LONGLONG limit." << std::endl;
								GlobalFree(lpszContentW);
								GlobalFree(lpByte);
								InternetCloseHandle(hRequest);
								InternetCloseHandle(hSession);
								InternetCloseHandle(hInternet);
								return FALSE;
							}
							set->insert(userid);
							lpszLine = wcstok_s(NULL, L"\n", &next);
						}
					}
					GlobalFree(lpszContentW);
				}
			}
		}
		GlobalFree(lpByte);
		InternetCloseHandle(hRequest);
	}
	InternetCloseHandle(hSession);
	InternetCloseHandle(hInternet);
	return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc == 4) {
		WCHAR szBearerToken[128];
		if (!GetTwitterBearerToken(argv[1], argv[2], szBearerToken, _countof(szBearerToken))) {
			std::wcout << "error: get bearer token.";
		}
		else {
			std::set<LONGLONG> friends;
			std::set<LONGLONG> followers;
			if (GetFollowWithoutFollower(szBearerToken, argv[3], L"followers", &followers) &&
				GetFollowWithoutFollower(szBearerToken, argv[3], L"friends", &friends)) {
				for (auto user : friends)
				{
					if (followers.count(user) == 0)
					{
						std::wcout << user << std::endl;
					}
				}
			}
		}
	}
	else {
		wprintf(L"Usage: GETTWITTERFOLLOWWITHOUTFOLLOWER <ConsumerKey> <ConsumerSecret> <TwitterID>\r\n");
	}
	return 0;
}
