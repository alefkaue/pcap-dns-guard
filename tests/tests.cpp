#include "pcap_guard.hpp"
#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
using V = std::vector<std::uint8_t>;
void check(bool b) { if (!b) throw std::runtime_error("assertion failed"); }
void be16(V& b, std::size_t p, std::uint16_t n) { b[p] = static_cast<std::uint8_t>(n >> 8); b[p+1] = static_cast<std::uint8_t>(n); }
void le32(V& b, std::size_t p, std::uint32_t n) { for (std::size_t i=0;i<4;i++) b[p+i]=static_cast<std::uint8_t>(n>>(8*i)); }
V frame() { V b(14+20+8+19); be16(b,12,0x0800); b[14]=0x45; be16(b,16,47); b[23]=17; be16(b,34,1234); be16(b,36,53); be16(b,38,27); be16(b,46,1); b[54]=1; b[55]='a'; b[56]=0; be16(b,57,1); be16(b,59,1); return b; }
V pcap(const V& frame) { V b(40+frame.size()); b[0]=0xd4;b[1]=0xc3;b[2]=0xb2;b[3]=0xa1;b[4]=2;b[6]=4;le32(b,16,65535);le32(b,20,1);le32(b,32,static_cast<std::uint32_t>(frame.size()));le32(b,36,static_cast<std::uint32_t>(frame.size()));std::copy(frame.begin(),frame.end(),b.begin()+40);return b; }
void reject(const V& b) { try { (void)pcap_guard::inspect(b); } catch(const std::runtime_error&) { return; } throw std::runtime_error("accepted invalid container"); }
int main() {
    int passed=0,failed=0;
    auto test=[&](const char* name,const std::function<void()>& body){ try{body();++passed;std::cout<<"PASS "<<name<<'\n';}catch(const std::exception& e){++failed;std::cout<<"FAIL "<<name<<": "<<e.what()<<'\n';}};
    test("valid synthetic query",[]{auto r=pcap_guard::inspect(pcap(frame()));check(r.packets==1&&r.dns_questions==1&&r.malformed==0);});
    test("truncated global header",[]{reject(V(23));});
    test("PCAPNG explicitly rejected",[]{auto b=pcap(frame());b[0]=0x0a;b[1]=0x0d;b[2]=0x0d;b[3]=0x0a;reject(b);});
    test("record length cannot exceed file",[]{auto b=pcap(frame());le32(b,32,600);reject(b);});
    test("captured cannot exceed original",[]{auto b=pcap(frame());le32(b,36,1);reject(b);});
    test("snaplen enforced",[]{auto b=pcap(frame());le32(b,16,1);reject(b);});
    test("timestamp fractional bounds",[]{auto b=pcap(frame());le32(b,28,1000000);reject(b);});
    test("unsupported link type",[]{auto b=pcap(frame());le32(b,20,101);reject(b);});
    test("truncated Ethernet",[]{check(pcap_guard::inspect(pcap(V(5))).malformed==1);});
    test("IPv4 fragments are skipped",[]{auto b=frame();be16(b,20,0x2000);auto r=pcap_guard::inspect(pcap(b));check(r.skipped==1&&r.dns_questions==0);});
    test("truncated capture remains incomplete",[]{auto b=frame();be16(b,16,100);auto r=pcap_guard::inspect(pcap(b));check(r.truncated==1&&r.malformed==0);});
    test("UDP length checked",[]{auto b=frame();be16(b,38,500);check(pcap_guard::inspect(pcap(b)).malformed==1);});
    test("pointer loop rejected",[]{auto b=frame();b[54]=0xc0;b[55]=12;check(pcap_guard::inspect(pcap(b)).malformed==1);});
    test("label truncation rejected",[]{auto b=frame();b[54]=63;check(pcap_guard::inspect(pcap(b)).malformed==1);});
    test("question count budget",[]{auto b=frame();be16(b,46,100);check(pcap_guard::inspect(pcap(b)).malformed==1);});
    test("non DNS UDP skipped",[]{auto b=frame();be16(b,36,12345);check(pcap_guard::inspect(pcap(b)).skipped==1);});
    test("responses not counted as queries",[]{auto b=frame();be16(b,44,0x8000);check(pcap_guard::inspect(pcap(b)).dns_questions==0);});
    test("every prefix is safely rejected or classified",[]{auto b=pcap(frame());for(std::size_t i=0;i<b.size();i++){try{(void)pcap_guard::inspect(std::span(b.data(),i));}catch(const std::runtime_error&){}}});
    test("single byte mutations remain bounded",[]{auto base=pcap(frame());for(std::size_t i=0;i<base.size();i++){auto b=base;b[i]^=0xff;try{(void)pcap_guard::inspect(b);}catch(const std::runtime_error&){}}});
    std::cout<<passed<<'/'<<passed+failed<<" passed\n";return failed?1:0;
}
