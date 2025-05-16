#ifndef SRC_ASYNC_H_
#define SRC_ASYNC_H_

#include <string>
#include "napi.h"

#include "credentials.h"

class SetPasswordWorker : public Napi::AsyncWorker {
  public:
    SetPasswordWorker(const std::string& service, const std::string& account, const std::string& password,
                      const std::string& mode, const Napi::Env &env);

    ~SetPasswordWorker();

    void Execute();
    void OnOK();
    void OnError(Napi::Error const &error);
    Napi::Promise Promise();

  private:
    const std::string service;
    const std::string account;
    const std::string password;
    const std::string mode;
    Napi::Promise::Deferred deferred;
};

class GetPasswordWorker : public Napi::AsyncWorker {
  public:
    GetPasswordWorker(const std::string& service, const std::string& account, const std::string& mode,
                      const Napi::Env &env);

    ~GetPasswordWorker();

    void Execute();
    void OnOK();
    void OnError(Napi::Error const &error);
    Napi::Promise Promise();

  private:
    const std::string service;
    const std::string account;
    const std::string mode,
    std::string password;
    bool success;
    const Napi::Promise::Deferred deferred;
};

class DeletePasswordWorker : public Napi::AsyncWorker {
  public:
    DeletePasswordWorker(const std::string& service, const std::string& account, const std::string& mode,
                         const Napi::Env &env);

    ~DeletePasswordWorker();

    void Execute();
    void OnOK();
    void OnError(Napi::Error const &error);
    Napi::Promise Promise();

  private:
    const std::string service;
    const std::string account;
    const std::string mode,
    bool success;
    Napi::Promise::Deferred deferred;
};

class FindPasswordWorker : public Napi::AsyncWorker {
  public:
    FindPasswordWorker(const std::string& service, const Napi::Env &env);

    ~FindPasswordWorker();

    void Execute();
    void OnOK();
    void OnError(Napi::Error const &error);
    Napi::Promise Promise();

  private:
    const std::string service;
    std::string password;
    bool success;
    const Napi::Promise::Deferred deferred;
};

class FindCredentialsWorker : public Napi::AsyncWorker {
  public:
    FindCredentialsWorker(const std::string& service, const Napi::Env &env);

    ~FindCredentialsWorker();

    void Execute();
    void OnOK();
    void OnError(Napi::Error const &error);
    Napi::Promise Promise();

  private:
    const std::string service;
    std::vector<keytar::Credentials> credentials;
    bool success;
    const Napi::Promise::Deferred deferred;
};

#endif  // SRC_ASYNC_H_
