#include <Security/Security.h>
#include "keytar.h"
#include "credentials.h"


namespace keytar {

/**
 * Converts a CFString to a std::string
 *
 * This either uses CFStringGetCStringPtr or (if that fails)
 * CFStringGetCString, trying to be as efficient as possible.
 */
const std::string CFStringToStdString(CFStringRef cfstring) {
  const char* cstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8);

  if (cstr != NULL) {
    return std::string(cstr);
  }

  CFIndex length = CFStringGetLength(cfstring);
  // Worst case: 2 bytes per character + NUL
  CFIndex cstrPtrLen = length * 2 + 1;
  char* cstrPtr = static_cast<char*>(malloc(cstrPtrLen));

  Boolean result = CFStringGetCString(cfstring,
                                      cstrPtr,
                                      cstrPtrLen,
                                      kCFStringEncodingUTF8);

  std::string stdstring;
  if (result) {
    stdstring = std::string(cstrPtr);
  }

  free(cstrPtr);

  return stdstring;
}

const std::string errorStatusToString(OSStatus status) {
  std::string errorStr;
  CFStringRef errorMessageString = SecCopyErrorMessageString(status, NULL);

  const char* errorCStringPtr = CFStringGetCStringPtr(errorMessageString,
                                                      kCFStringEncodingUTF8);
  if (errorCStringPtr) {
    errorStr = std::string(errorCStringPtr);
  } else {
    errorStr = std::string("An unknown error occurred.");
  }

  CFRelease(errorMessageString);
  return errorStr;
}

//=====================Non Legacy Mode (NL) start=====================
const bool isModeNL(const std::string& mode) {
   bool result = (mode == "non-legacy");
   return result;
}

KEYTAR_OP_RESULT AddPasswordNL(const std::string& service,
                               const std::string& account,
                               const std::string& password,
                               std::string* error) {
  CFStringRef serviceStr = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);
  CFStringRef accountStr = CFStringCreateWithCString(NULL, account.c_str(), kCFStringEncodingUTF8);
  CFDataRef passwordData = CFDataCreate(NULL, reinterpret_cast<const UInt8*>(password.data()), password.length());

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecAttrService, serviceStr);
  CFDictionaryAddValue(query, kSecAttrAccount, accountStr);
  CFDictionaryAddValue(query, kSecValueData, passwordData);
  CFDictionaryAddValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
  CFDictionaryAddValue(query, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);

  OSStatus status = SecItemAdd(query, NULL);

  CFRelease(serviceStr);
  CFRelease(accountStr);
  CFRelease(passwordData);
  CFRelease(query);

  if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT UpdatePasswordNL(const std::string& service,
                                  const std::string& account,
                                  const std::string& password,
                                  std::string* error) {
  CFStringRef serviceStr = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);
  CFStringRef accountStr = CFStringCreateWithCString(NULL, account.c_str(), kCFStringEncodingUTF8);
  CFDataRef passwordData = CFDataCreate(NULL, reinterpret_cast<const UInt8*>(password.data()), password.length());

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecAttrService, serviceStr);
  CFDictionaryAddValue(query, kSecAttrAccount, accountStr);
  CFDictionaryAddValue(query, kSecAttrSynchronizable, kCFBooleanFalse);

  CFMutableDictionaryRef update = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(update, kSecValueData, passwordData);

  OSStatus status = SecItemUpdate(query, update);

  CFRelease(serviceStr);
  CFRelease(accountStr);
  CFRelease(passwordData);
  CFRelease(query);
  CFRelease(update);

  if (status == errSecItemNotFound) {
    return AddPasswordNL(service, account, password, error);
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT DeletePasswordNL(const std::string& service,
                                  const std::string& account,
                                  std::string* error) {
  CFStringRef serviceStr = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);
  CFStringRef accountStr = CFStringCreateWithCString(NULL, account.c_str(), kCFStringEncodingUTF8);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecAttrService, serviceStr);
  CFDictionaryAddValue(query, kSecAttrAccount, accountStr);
  CFDictionaryAddValue(query, kSecAttrSynchronizable, kCFBooleanFalse);

  OSStatus status = SecItemDelete(query);

  CFRelease(serviceStr);
  CFRelease(accountStr);
  CFRelease(query);

  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT GetPasswordNL(const std::string& service,
                               const std::string& account,
                               std::string* password,
                               std::string* error) {
    CFStringRef serviceStr = CFStringCreateWithCString(NULL, service.c_str(), kCFStringEncodingUTF8);
    CFStringRef accountStr = CFStringCreateWithCString(NULL, account.c_str(), kCFStringEncodingUTF8);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionaryAddValue(query, kSecAttrService, serviceStr);
    CFDictionaryAddValue(query, kSecAttrAccount, accountStr);
    CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);
    CFDictionaryAddValue(query, kSecAttrSynchronizable, kCFBooleanFalse);
    
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(serviceStr);
    CFRelease(accountStr);
    CFRelease(query);
    if (status == errSecItemNotFound) return FAIL_NONFATAL;
    if (status != errSecSuccess) {
        *error = errorStatusToString(status);
        return FAIL_ERROR;
    }
    CFDataRef resultData = static_cast<CFDataRef>(result);
    *password = std::string(reinterpret_cast<const char*>(CFDataGetBytePtr(resultData)), CFDataGetLength(resultData));
    CFRelease(result);
    return SUCCESS;
}
//=====================Non Legacy Mode (NL) end=====================

KEYTAR_OP_RESULT AddPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* error) {
  OSStatus status = SecKeychainAddGenericPassword(NULL,
                                                  service.length(),
                                                  service.data(),
                                                  account.length(),
                                                  account.data(),
                                                  password.length(),
                                                  password.data(),
                                                  NULL);

  if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT SetPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             const std::string& mode,
                             std::string* error) {
  if (isModeNL(mode)){
      return UpdatePasswordNL(service, account, password, error);
  }
    
  SecKeychainItemRef item;
  OSStatus result = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   NULL,
                                                   NULL,
                                                   &item);

  if (result == errSecItemNotFound) {
    return AddPassword(service, account, password, error);
  } else if (result != errSecSuccess) {
    *error = errorStatusToString(result);
    return FAIL_ERROR;
  }

  result = SecKeychainItemModifyAttributesAndData(item,
                                                  NULL,
                                                  password.length(),
                                                  password.data());
  CFRelease(item);
  if (result != errSecSuccess) {
    *error = errorStatusToString(result);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT GetPassword(const std::string& service,
                             const std::string& account,
                             const std::string& mode,
                             std::string* password,
                             std::string* error) {
  if (isModeNL(mode)){
      return GetPasswordNL(service, account, password, error);
  }
    
  void *data;
  UInt32 length;
  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   &length,
                                                   &data,
                                                   NULL);

  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  *password = std::string(reinterpret_cast<const char*>(data), length);
  SecKeychainItemFreeContent(NULL, data);
  return SUCCESS;
}

KEYTAR_OP_RESULT DeletePassword(const std::string& service,
                                const std::string& account,
                                const std::string& mode,
                                std::string* error) {
  if (isModeNL(mode)){
     return DeletePasswordNL(service, account, error);
  }
    
  SecKeychainItemRef item;
  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   NULL,
                                                   NULL,
                                                   &item);
  if (status == errSecItemNotFound) {
    // Item could not be found, so already deleted.
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  status = SecKeychainItemDelete(item);
  CFRelease(item);
  if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT FindPassword(const std::string& service,
                              std::string* password,
                              std::string* error) {
  SecKeychainItemRef item;
  void *data;
  UInt32 length;

  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   0,
                                                   NULL,
                                                   &length,
                                                   &data,
                                                   &item);
  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  *password = std::string(reinterpret_cast<const char*>(data), length);
  SecKeychainItemFreeContent(NULL, data);
  CFRelease(item);
  return SUCCESS;
}

Credentials getCredentialsForItem(CFDictionaryRef item) {
  CFStringRef service = (CFStringRef) CFDictionaryGetValue(item,
                                                           kSecAttrService);
  CFStringRef account = (CFStringRef) CFDictionaryGetValue(item,
                                                           kSecAttrAccount);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL,
    0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  CFDictionaryAddValue(query, kSecAttrService, service);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne);
  CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecAttrAccount, account);

  Credentials cred;
  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

  CFRelease(query);

  if (status == errSecSuccess) {
      CFDataRef passwordData = (CFDataRef) CFDictionaryGetValue(
        (CFDictionaryRef) result,
        CFSTR("v_Data"));
      CFStringRef password = CFStringCreateFromExternalRepresentation(
        NULL,
        passwordData,
        kCFStringEncodingUTF8);

      cred = Credentials(
        CFStringToStdString(account),
        CFStringToStdString(password));

      CFRelease(password);
  }

  if (result != NULL) {
    CFRelease(result);
  }

  return cred;
}

KEYTAR_OP_RESULT FindCredentials(const std::string& service,
                                 std::vector<Credentials>* credentials,
                                 std::string* error) {
  CFStringRef serviceStr = CFStringCreateWithCString(
    NULL,
    service.c_str(),
    kCFStringEncodingUTF8);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL,
    0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecAttrService, serviceStr);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);

  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

  CFRelease(serviceStr);
  CFRelease(query);

  if (status == errSecSuccess) {
    CFArrayRef resultArray = (CFArrayRef) result;
    int resultCount = CFArrayGetCount(resultArray);

    for (int idx = 0; idx < resultCount; idx++) {
      CFDictionaryRef item = (CFDictionaryRef) CFArrayGetValueAtIndex(
        resultArray,
        idx);

      Credentials cred = getCredentialsForItem(item);
      credentials->push_back(cred);
    }
  } else if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  if (result != NULL) {
    CFRelease(result);
  }

  return SUCCESS;
}

}  // namespace keytar
