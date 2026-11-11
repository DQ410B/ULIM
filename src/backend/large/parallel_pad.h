#pragma once
// Local CPU work only. No IO, PRG, OT cursor, or observer callback is shared.
#include <openssl/sha.h>
#include <algorithm>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ulim_parallel_pad {
enum class HashMode { OneShot, Context };

inline HashMode environment_hash_mode() {
    const char* value=std::getenv("ULIM_OT_HASH_MODE");
    if(!value||std::strcmp(value,"oneshot")==0)return HashMode::OneShot;
    if(std::strcmp(value,"context")==0)return HashMode::Context;
    throw std::runtime_error("ULIM_OT_HASH_MODE must be oneshot or context");
}
inline unsigned environment_workers() {
    const char* value=std::getenv("ULIM_OT_THREADS");
    if(!value)return 1;
    for(unsigned n:{1u,2u,4u,8u})if(std::string(value)==std::to_string(n))return n;
    throw std::runtime_error("ULIM_OT_THREADS must be 1,2,4,8");
}
inline void digest65(const unsigned char* input,unsigned char* output,HashMode mode) {
    // Both APIs implement exactly SHA-256 of the same 65 bytes. The explicit
    // output and per-call context prevent shared digest storage.
    if(mode==HashMode::OneShot) {
        if(SHA256(input,65,output)==nullptr)
            throw std::runtime_error("parallel OT SHA256 failure");
    } else {
        SHA256_CTX context;
        if(SHA256_Init(&context)!=1||SHA256_Update(&context,input,65)!=1||
           SHA256_Final(output,&context)!=1)
            throw std::runtime_error("parallel OT SHA256 context failure");
    }
}

// Synchronous owner-thread interface. Background workers sleep between jobs;
// the calling thread participates, so 'workers' includes that calling thread.
// The callback must give each public group exclusive output-byte ownership.
class Workers {
    using Job=std::function<void(size_t,size_t)>;
    const unsigned count_;
    const HashMode mode_;
    const std::thread::id owner_=std::this_thread::get_id();
    std::vector<std::thread> threads_;
    std::mutex mutex_;
    std::condition_variable start_,done_;
    std::shared_ptr<const Job> job_;
    size_t groups_=0,remaining_=0,generation_=0;
    bool stopping_=false,active_=false;
    std::exception_ptr failure_;

    void failure(std::exception_ptr error) {
        std::lock_guard<std::mutex> lock(mutex_);
        if(!failure_)failure_=std::move(error);
    }
    void worker(unsigned id) noexcept {
        size_t seen=0;
        for(;;) {
            std::shared_ptr<const Job> task;
            size_t lo,hi;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                start_.wait(lock,[&]{return stopping_||generation_!=seen;});
                if(stopping_)return;
                seen=generation_;task=job_;
                lo=groups_*id/count_;hi=groups_*(id+1)/count_;
            }
            try {(*task)(lo,hi);}catch(...) {failure(std::current_exception());}
            task.reset();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if(--remaining_==0)done_.notify_one();
            }
        }
    }
    void start_workers() {
        if(!threads_.empty()||count_==1)return;
        try {
            threads_.reserve(count_-1);
            for(unsigned id=1;id<count_;++id)
                threads_.emplace_back([this,id]{worker(id);});
        } catch(...) {
            shutdown();
            throw;
        }
    }
    void shutdown() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_=true;
        }
        start_.notify_all();
        for(auto& thread:threads_)if(thread.joinable())thread.join();
    }
public:
    explicit Workers(unsigned count,HashMode mode):count_(count),mode_(mode) {
        if(count!=1&&count!=2&&count!=4&&count!=8)
            throw std::runtime_error("unsupported OT worker count");
    }
    Workers():Workers(environment_workers(),environment_hash_mode()){}
    ~Workers(){shutdown();}
    Workers(const Workers&)=delete;
    Workers& operator=(const Workers&)=delete;
    unsigned count()const{return count_;}
    HashMode mode()const{return mode_;}
    void run(size_t groups,Job function) {
        if(std::this_thread::get_id()!=owner_)
            throw std::runtime_error("OT CPU pool must be called by its owner");
        if(active_)throw std::runtime_error("reentrant OT CPU pool request");
        if(groups==0)return;
        start_workers();
        auto task=std::make_shared<const Job>(std::move(function));
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if(stopping_)throw std::runtime_error("OT CPU pool is stopped");
            active_=true;groups_=groups;remaining_=count_-1;job_=task;
            failure_=nullptr;++generation_;
        }
        start_.notify_all();
        try {(*task)(0,groups/count_);}catch(...) {failure(std::current_exception());}
        std::exception_ptr error;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            done_.wait(lock,[&]{return remaining_==0;});
            error=failure_;job_.reset();groups_=0;active_=false;
        }
        if(error)std::rethrow_exception(error);
    }
};
} // namespace ulim_parallel_pad
