#include <iostream>
#include <unordered_map>

#define MAX_PROXY_CONNECTIONS 100
#define PROXYING_FOR_LEGACY true
#define FORCE_PROXY_CONNECTIONS false

#define ENABLE_HTTP true
#define ENABLE_EXIT_ENDPOINT false

// If a motd.txt exists, send it to users after first binding via an invite.
#ifndef ENABLE_MOTD
	#define ENABLE_MOTD false
#endif

// Opportunistically ask clients for an introduction in an attempt to grab their username and buildId.
#define REQUEST_INTRODUCTION true

#ifndef THIS_SERVER_ID
	#define THIS_SERVER_ID 0
#endif
#define JITTER false

#include <crc32.hpp>
#include <crc32c.hpp>
#if MULTI_NRS
#include <dnsResolver.hpp>
#endif
#if ENABLE_HTTP
#include <HttpRequest.hpp>
#endif
#include <json.hpp>
#include <lzf.hpp>
#include <main.hpp>
#include <md5.hpp>
#include <MemoryRefReader.hpp>
#include <netAdaptor.hpp>
#include <netInfo.hpp>
#if JITTER
#include <os.hpp>
#endif
#if MAX_PROXY_CONNECTIONS > 0 || JITTER
#include <rand.hpp>
#endif
#include <Server.hpp>
#include <ServerServiceUdp.hpp>
#if ENABLE_HTTP
#include <ServerWebService.hpp>
#endif
#include <Socket.hpp>
#include <string.hpp>
#include <StringWriter.hpp>
#include <time.hpp>
#include <utility.hpp>

#ifdef DOCKER
#include <signal.h>
#endif

#if USE_DTLSBRIDGE
extern "C"
{
	// inputData may be modified. Returns true if input data could successfully be decoded as DTLS traffic.
	bool ReadData(uint8_t* inputData, size_t inputDataLength, uint8_t* pendingSendBuffer, size_t* pendingSendLength, uint8_t decryptedDataBuffer[4096], size_t* decryptedDataLength, const char* endpoint);
	void WriteData(const uint8_t* rawData, size_t rawDataLength, uint8_t* encryptedData, size_t* encryptedDataLength, const char* endpoint);
	void init();
	void deinit();
}
#endif

using namespace soup;

static void udp_send(Socket& s, const SocketAddr& addr, const std::string& data, bool is_dtls)
{
#if USE_DTLSBRIDGE
	if (is_dtls)
	{
		uint8_t encryptedData[4096];
		size_t encryptedDataLength = 0;
		std::string endpoint = addr.toString();
		WriteData((const uint8_t*)data.data(), data.size(), encryptedData, &encryptedDataLength, endpoint.c_str());
		if (encryptedDataLength > 0)
		{
			s.udpServerSend(addr, (const char*)encryptedData, encryptedDataLength);
		}
		return;
	}
#endif
	s.udpServerSend(addr, data);
}

static bool is_u10_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641ab7"
		|| salt == "6f7fd17e0eb641ab6"
		|| salt == "3bd61b742870d0bb3"
		;
}

static bool is_u11_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641abC"
		|| is_u10_or_below(salt)
		;
}

static bool is_u12_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641abD"
		|| is_u11_or_below(salt)
		;
}

static bool is_u15_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641abH"
		|| salt == "6f7fd17e0eb641abF"
		|| salt == "6f7fd17e0eb641abE"
		|| is_u12_or_below(salt)
		;
}

static bool is_u15_14_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641abN"
		|| is_u15_or_below(salt)
		;
}

static bool is_u16_or_below(const std::string_view& salt)
{
	return salt == "6f7fd17e0eb641abP"
		|| is_u15_14_or_below(salt)
		;
}

static bool is_u26_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387B"
		|| salt == "b471e49539930dc9b5a131e6247c7387A"
		|| salt == "6f7fd17e0eb641abQ"
		|| is_u16_or_below(salt)
		;
}

static bool is_u27_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387D"
		|| is_u26_or_below(salt)
		;
}

static bool is_u32_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387E"
		|| is_u27_or_below(salt)
		;
}

static bool is_u35_or_below(const std::string_view& salt)
{
	return salt == "b471e49539930dc9b5a131e6247c7387F"
		|| is_u32_or_below(salt)
		;
}

static uint64_t md5_checksum(const char* data, size_t size, const std::string_view& salt)
{
	md5::State st;
	st.append(data, size);
	st.append(salt.data(), salt.size());
	union {
		uint8_t digest[md5::DIGEST_BYTES];
		uint64_t chksum64;
	} u;
	st.finalise();
	st.getDigest(u.digest);
	return u.chksum64;
}

static std::string compressPacket(std::string&& data)
{
	uint16_t decompressed_size = data.size() - 1;
	uint8_t buffer[0x1000];
	if (decompressed_size <= 0x3F)
	{
		if (auto compressed_size = lzf::compress(data.data() + 1, data.size() - 1, buffer + 1, sizeof(buffer) - 1);
			compressed_size != 0 && (compressed_size + 1) < data.size()
			)
		{
			buffer[0] = decompressed_size;
			return std::string((const char*)buffer, compressed_size + 1);
		}
	}
	else
	{
		if (auto compressed_size = lzf::compress(data.data() + 1, data.size() - 1, buffer + 2, sizeof(buffer) - 2);
			compressed_size != 0 && (compressed_size + 2) < data.size()
			)
		{
			buffer[0] = (decompressed_size >> 6) | 0xC0;
			buffer[1] = (decompressed_size & 0x3F) | 0x80;
			return std::string((const char*)buffer, compressed_size + 2);
		}
	}
	return data;
}

static std::string packData(const std::string& data, const std::string_view& salt)
{
	StringWriter sw;

	sw.skip(!is_u11_or_below(salt) ? 5 : 9); // placeholder for compression byte + CRC

	uint32_t magic = 0x80000000;
	sw.u32_le(magic);

	sw.str_lp<u16_le_t>(data);

	if (!is_u11_or_below(salt)) // >= U12
	{
		if (!is_u32_or_below(salt))
		{
			uint32_t initial = crc32c::hash((const uint8_t*)sw.data.data() + 5, sw.data.size() - 5);
			*(uint32_t*)(sw.data.data() + 1) = Endianness::toNetwork(crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial));
		}
		else
		{
			uint32_t initial = crc32::hash((const uint8_t*)sw.data.data() + 5, sw.data.size() - 5);
			*(uint32_t*)(sw.data.data() + 1) = Endianness::toNetwork(crc32::hash((const uint8_t*)salt.data(), salt.size(), initial));	
		}
	}
	else
	{
		*(uint64_t*)(sw.data.data() + 1) = md5_checksum(sw.data.data() + 9, sw.data.size() - 9, salt);
	}

	//std::cout << "Server says: " << string::bin2hex(sw.data) << std::endl;

#if true
	return compressPacket(std::move(sw.data));
#else
	SOUP_MOVE_RETURN(sw.data);
#endif
}

static bool unpackData(const SocketAddr& addr, MemoryRefReader& sr, std::string& data/*, network_u16_t proxy_port = 0*/)
{
	uint8_t unk_byte;
	sr.u8(unk_byte);
	if (unk_byte != 0)
	{
		uint16_t expected_decompressed_size = unk_byte;
		if (unk_byte & 0x80)
		{
			expected_decompressed_size &= 0x3F;
			while (unk_byte & 0x40)
			{
				sr.u8(unk_byte);
				expected_decompressed_size <<= 6;
				expected_decompressed_size |= unk_byte & 0x3F;
			}
		}

		char buffer[0x1000];
		const auto decompressed_size = lzf::decompress(data.data() + sr.getPosition(), data.size() - sr.getPosition(), buffer, sizeof(buffer));
		if (decompressed_size != expected_decompressed_size)
		{
			std::cout << addr.toString();
			/*if (proxy_port)
			{
				std::cout << " to proxy port " << Endianness::toNative(proxy_port);
			}*/
			std::cout << " - Decompressed size mismatch (got " << decompressed_size << ", expected " << expected_decompressed_size << "): " << string::bin2hex(data) << std::endl;
			return false;
		}
		data = std::string(buffer, decompressed_size);
		sr = MemoryRefReader(data);
	}
	return true;
}

template <typename T>
static bool ser_str(T& s, const std::string_view& salt, std::string& str)
{
	uint32_t len = str.size();
	if (is_u35_or_below(salt))
	{
		s.u32_le(len);
	}
	else
	{
		s.oml(len);
	}
	return s.str(len, str);
}

union MongoId
{
	uint32_t ints[3];
	uint8_t bytes[12];

	MongoId()
	{
		memset(ints, 0, 12);
	}

	MongoId(const std::string& str)
	{
		operator=(str);
	}

	void operator=(const std::string& str) noexcept
	{
		size_t size = str.size();
		if (size > 12)
		{
			size = 12;
		}
		memset(ints, 0, 12);
		memcpy(ints, str.data(), size);
	}

	bool operator==(const MongoId& b) const noexcept
	{
		return memcmp(ints, b.ints, 12) == 0;
	}

	template <typename T>
	bool io(T& s)
	{
		return s.raw(ints, 12);
	}

	std::string toString() const noexcept
	{
		return string::bin2hexLower((const char*)ints, 12);
	}

	uint32_t getProcessHash() const noexcept
	{
		uint32_t hash = 2166136261u;
		for (auto i = 4; i != 9; ++i)
		{
			hash ^= bytes[i];
			hash *= 16777619u;
		}
		return hash;
	}
};

namespace std
{
	template<>
	struct hash<MongoId>
	{
		size_t operator()(const MongoId& id) const noexcept
		{
			uint64_t hash = 0;
			for (const uint32_t& i : id.ints)
			{
				hash += i;
				hash *= 6364136223846793005ull;
				hash += 1442695040888963407ull;
			}
			return hash;
		}
	};
}

enum NatBehaviour : uint8_t
{
	NAT_UNK,
	NAT_TRANSPARENT,
	NAT_STRICT,
};

struct AccountData
{
	native_u32_t reflexive_ip;
	native_u32_t local_ip;

	native_u16_t reflexive_port_client = 4955;
	native_u16_t reflexive_port_server = 4950;
	native_u16_t local_port_client = 4955;
	native_u16_t local_port_server = 4950;

	std::string_view salt;
	bool is_dtls;
#if ENABLE_MOTD
	bool sent_motd = false;
#endif
#if REQUEST_INTRODUCTION
	NatBehaviour nat_behaviour = NAT_UNK;
#endif

	uint8_t status; // presence state
	std::string presence; // presence is a json object. exact format depends on version, e.g. U41.1 changed "level" to "l", etc.

	time_t last_nat_bind;

	std::string username;
#if REQUEST_INTRODUCTION
	int64_t buildId = 0;
#endif

	bool isActive() const noexcept
	{
		return time::unixSecondsSince(last_nat_bind) <= 120;
	}

	void sendGameInvite(Socket& s, const MongoId& inviter_acctId, const MongoId& invitee_acctId, const std::string& session_info, const std::string& inviter_name, uint8_t presence_state = 3, uint8_t bindingServerId = THIS_SERVER_ID)
	{
		StringWriter sw;
		{ uint8_t b = 0x7c /* 31 << 2 */; sw.u8(b); }
		const_cast<MongoId&>(inviter_acctId).io(sw);
		if (!is_u15_or_below(salt))
		{
			if (!is_u15_14_or_below(salt))
			{
				sw.u8(bindingServerId);
			}
			const_cast<MongoId&>(invitee_acctId).io(sw);
		}
		sw.u8(presence_state);
		ser_str(sw, this->salt, const_cast<std::string&>(session_info));
		ser_str(sw, this->salt, const_cast<std::string&>(inviter_name));
		std::string unk_str; ser_str(sw, this->salt, unk_str);
		udp_send(s, SocketAddr(this->reflexive_ip, this->reflexive_port_client), packData(sw.data, this->salt), this->is_dtls);
	}

	void sendSocialChange(Socket& s, uint8_t type, const std::string& json)
	{
		if (!is_u11_or_below(this->salt))
		{
			StringWriter sw;
			{ uint8_t b = 0xac; sw.u8(b); }
			sw.u8(type);
			ser_str(sw, this->salt, const_cast<std::string&>(json));
			udp_send(s, SocketAddr(this->reflexive_ip, this->reflexive_port_client), packData(sw.data, this->salt), this->is_dtls);
		}
	}

	void sendFriendRefresh(Socket& s, uint8_t unk = 9)
	{
		if (!is_u10_or_below(this->salt))
		{
			StringWriter sw;
			{ uint8_t b = 0x78; sw.u8(b); }
			sw.u8(unk);
			udp_send(s, SocketAddr(this->reflexive_ip, this->reflexive_port_client), packData(sw.data, this->salt), this->is_dtls);
		}
	}
};
static std::unordered_map<MongoId, AccountData> account_map;

#if ENABLE_HTTP || MULTI_NRS
static SharedPtr<Socket> nrs_socket;
#endif

#if MULTI_NRS
static std::unordered_map<MongoId, uint8_t> remote_account_map; // <account id, binding server id>

#if ENABLE_HTTP
static std::vector<std::string> get_servers_for_http_impl()
{
	const std::vector<const char*> strs = SERVERS;
	std::vector<std::string> hostnames;
	hostnames.reserve(strs.size());
	for (uint8_t i = 0; i != strs.size(); ++i)
	{
		std::string& hostname = hostnames.emplace_back(strs[i]);
		if (hostname.find(':') == std::string::npos)
		{
			hostname.append(":4950");
		}
	}
	return hostnames;
}

static const std::vector<std::string>& get_servers_for_http()
{
	static const std::vector<std::string> servers = get_servers_for_http_impl();
	return servers;
}
#endif

static std::vector<SocketAddr> get_servers_impl()
{
	const std::vector<const char*> strs = SERVERS;
	std::vector<SocketAddr> addrs;
	addrs.reserve(strs.size());
	auto resolver = dnsResolver::makeDefault();
	for (uint8_t i = 0; i != strs.size(); ++i)
	{
		if (strchr(strs[i], ':') == nullptr)
		{
			const auto ips = resolver->lookupIPv4(strs[i]);
			if (!ips.empty())
			{
				addrs.emplace_back(ips[0], (native_u16_t)4950);
				continue;
			}
		}
		addrs.emplace_back().fromString(strs[i]);
	}
	return addrs;
}

static const std::vector<SocketAddr>& get_servers()
{
	static const std::vector<SocketAddr> servers = get_servers_impl();
	return servers;
}

static void pack_custom_message(std::string& msg)
{
	msg.insert(0, 1, THIS_SERVER_ID);
	msg.insert(0, 1, '\1'); // NRS-to-NRS message
	msg.insert(0, 5, '\0'); // compression + checksum
	const std::string_view salt = "b471e49539930dc9b5a131e6247c7387A";
	const auto initial = crc32::hash((const uint8_t*)msg.data() + 5, msg.size() - 5, 0);
	*(uint32_t*)(msg.data() + 1) = Endianness::toNetwork(crc32::hash((const uint8_t*)salt.data(), salt.size(), initial));

	msg = compressPacket(std::move(msg));
}

static void send_custom_message(uint8_t bindingServerId, std::string&& msg)
{
	pack_custom_message(msg);
	if (nrs_socket)
	{
		nrs_socket->udpServerSend(get_servers()[bindingServerId], msg);
	}
	else
	{
		Socket s;
		s.udpClientSend(get_servers()[bindingServerId], msg);
	}
}

static void broadcast_custom_message(std::string&& msg)
{
	pack_custom_message(msg);
	const std::vector<SocketAddr>& servers = get_servers();
	if (nrs_socket)
	{
		for (uint8_t i = 0; i != servers.size(); ++i)
		{
			if (i != THIS_SERVER_ID)
			{
				nrs_socket->udpServerSend(servers[i], msg);
			}
		}
	}
	else
	{
		Socket s;
		for (uint8_t i = 0; i != servers.size(); ++i)
		{
			if (i != THIS_SERVER_ID)
			{
				s.udpClientSend(servers[i], msg);
			}
		}
	}
}
#endif

static std::unordered_map<MongoId, AccountData>::iterator erase_account(std::unordered_map<MongoId, AccountData>::iterator it)
{
#if MULTI_NRS
	broadcast_custom_message("-" + std::string((const char*)it->first.ints, 12));
#endif
	return account_map.erase(it);
}

static void collect_garbage()
{
	for (auto it = account_map.begin(); it != account_map.end(); )
	{
		if (it->second.isActive())
		{
			++it;
		}
		else
		{
			it = erase_account(it);
		}
	}
}

struct AccountResolveResponse
{
	MongoId account_id;
	uint32_t reflexive_ip = 0;
	uint32_t local_ip = 0;
	uint16_t reflexive_port = 0;
	uint16_t local_port = 0;
#if MULTI_NRS
	uint8_t bindingServerId = THIS_SERVER_ID;
	bool unresolved = false;
#endif

	void write(StringWriter& sw, const std::string_view& salt)
	{
		account_id.io(sw);

		if (!is_u26_or_below(salt)) // >= U27
		{
			if (reflexive_ip != 0)
			{
#if MULTI_NRS
				{ uint8_t b = 0x80 | (bindingServerId + 1); sw.u8(b); }
#else
				{ uint8_t b = 0x81; sw.u8(b); }
#endif
			_write_masked_ips:
				uint32_t masked_reflexive_ip = reflexive_ip ^ 0xAAAAAAAA;
				uint32_t masked_local_ip = local_ip ^ 0xAAAAAAAA;
				uint16_t masked_reflexive_port = reflexive_port ^ 0xAAAA;
				uint16_t masked_local_port = local_port ^ 0xAAAA;
				sw.u32_be(masked_reflexive_ip);
				sw.u16_le(masked_reflexive_port);
				sw.u32_be(masked_local_ip);
				sw.u16_le(masked_local_port);
			}
			else
			{
				uint8_t b = 0; sw.u8(b);
			}
		}
		else
		{
#if MULTI_NRS
			if (bindingServerId != THIS_SERVER_ID)
			{
				uint8_t b = ~bindingServerId; sw.u8(b);
			}
			else
#endif
			if (reflexive_ip != 0)
			{
				uint8_t b = 4; sw.u8(b);
				goto _write_masked_ips;
			}
			else
			{
				uint8_t b = 0; sw.u8(b);
			}
		}
	}

#if MULTI_NRS
	template <typename T>
	bool custom_io(T& s)
	{
		return account_id.io(s)
			&& s.u32_le(reflexive_ip)
			&& s.u32_le(local_ip)
			&& s.u16_le(reflexive_port)
			&& s.u16_le(local_port)
			&& s.u8(bindingServerId)
			&& s.b(unresolved)
			;
	}
#endif
};

struct C2STest
{
	MongoId acctId;
	uint64_t timestamp = 0;
	uint32_t local_ip = 0;
	uint16_t local_port = 0;
	std::string local_addr_str;

	void readU11U27(Reader& sr, const std::string_view& salt)
	{
		acctId.io(sr);
		if (is_u12_or_below(salt)) // < U13
		{
			sr.skip(64); // NatHash
		}
		sr.u32_be(local_ip); // U12 does not provide a local address
		sr.u16_le(local_port);
		if (!is_u15_or_below(salt)) // >= U15.14
		{
			ser_str(sr, salt, local_addr_str);
		}
	}

	bool readU28U29(Reader& sr)
	{
		return acctId.io(sr)
			&& sr.u32_be(local_ip)
			&& sr.u16_le(local_port)
			&& ser_str(sr, "b471e49539930dc9b5a131e6247c7387E", local_addr_str)
			&& !sr.hasMore()
			;
	}

	bool readU30U31(Reader& sr)
	{
		return acctId.io(sr)
			&& sr.u64_le(timestamp)
			&& sr.u32_be(local_ip)
			&& sr.u16_le(local_port)
			&& ser_str(sr, "b471e49539930dc9b5a131e6247c7387E", local_addr_str)
			&& !sr.hasMore()
			;
	}
};

struct ResolveResponse
{
	uint8_t task_id;
	std::vector<AccountResolveResponse> results;

	void write(StringWriter& sw, const std::string_view& salt)
	{
		{ uint8_t b = 0x68; sw.u8(b); }
		sw.u8(task_id);
		{ uint8_t num_results = results.size(); sw.u8(num_results); }
		for (auto& result : results)
		{
			result.write(sw, salt);
		}
	}

#if MULTI_NRS
	template <typename T>
	void custom_io(T& s)
	{
		s.u8(task_id);
		if constexpr (T::isRead())
		{
			uint8_t num_results = 0;
			s.u8(num_results);
			results.clear();
			results.reserve(num_results);
			while (num_results--)
			{
				results.emplace_back().custom_io(s);
			}
		}
		else
		{
			uint8_t num_results = results.size();
			s.u8(num_results);
			for (auto& result : results)
			{
				result.custom_io(s);
			}
		}
	}
#endif
};

enum IntroductionType : uint8_t
{
	IT_FROM_PEER = 0,
	IT_TO_PROXY = 1,
	IT_VIA_PROXY = 2, // "potential proxy"
};

static void send_introduction(Socket& s, const MongoId& from_acctId, const MongoId& to_acctId, const SocketAddr& from_addr, const SocketAddr& to_addr, IntroductionType it, uint8_t task_id, const std::string_view& salt, bool is_dtls)
{
	StringWriter sw;
	if (!is_u10_or_below(salt)) // >= U11
	{
		{ uint8_t b = 0x70 /* 28 << 2 */; sw.u8(b); }
		sw.u8(task_id);
		if (!is_u15_or_below(salt))
		{
			uint32_t ip = from_addr.ip.getV4NativeEndian();
			uint16_t port = from_addr.getPort();

			ip ^= 0xAAAAAAAA;
			port ^= 0xAAAA;

			{ uint8_t b = it; sw.u8(b); }
			const_cast<MongoId&>(from_acctId).io(sw);
			const_cast<MongoId&>(to_acctId).io(sw);
			sw.u32_be(ip);
			sw.u16_le(port);
		}
		else
		{
			std::string tmp = from_acctId.toString();
			ser_str(sw, salt, tmp);
			tmp = to_acctId.toString();
			ser_str(sw, salt, tmp);
			tmp = from_addr.toString();
			ser_str(sw, salt, tmp);
		}
	}
	else
	{
		{ uint8_t b = 24 << 2; sw.u8(b); }
		std::string tmp = from_acctId.toString();
		ser_str(sw, salt, tmp);
		tmp = to_acctId.toString();
		ser_str(sw, salt, tmp);
		tmp = from_addr.toString();
		ser_str(sw, salt, tmp);
		tmp = std::string(1, task_id);
		ser_str(sw, salt, tmp);
	}
	udp_send(s, to_addr, packData(sw.data, salt), is_dtls);
}

static network_u32_t this_machine_ip = 0;
#if MAX_PROXY_CONNECTIONS > 0
struct Proxy : public ServerServiceUdp
{
	MongoId left_id;
	MongoId right_id;
	network_u32_t left_ip;
	network_u32_t right_ip;
	network_u16_t left_port = 0xffff;
	network_u16_t right_port = 0xffff;
	network_u16_t port;
	bool left_is_server;
	bool right_is_server;
	time_t last_traffic = 0;

	Proxy()
		: ServerServiceUdp(&staticCallback)
	{
	}

	static void staticCallback(Socket& s, SocketAddr&& addr, std::string&& data, ServerServiceUdp& srv)
	{
		static_cast<Proxy&>(srv).callback(s, std::move(addr), std::move(data));
	}

	void callback(Socket& s, SocketAddr&& addr, std::string&& data)
	{
		//std::cout << addr.toString() << " - Traffic on proxy port " << Endianness::toNative(port) << ": " << string::bin2hex(data) << std::endl;

		SOUP_IF_UNLIKELY (left_port == 0 || right_port == 0) // Setup phase?
		{
			// I think it's rather unlikely that someone's account id can be LZF-compressed away,
			// and the problem if we decompress the data now is that we can't cleanly forward it anymore.

			/*MemoryRefReader sr(data);
			SOUP_IF_UNLIKELY (!unpackData(addr, sr, data, this->port))
			{
				return;
			}*/

			auto left_id_pos = data.find((const char*)left_id.ints, 0, 12);
			if (left_id_pos == std::string::npos)
			{
				left_id_pos = data.find(left_id.toString());
			}
			auto right_id_pos = data.find((const char*)right_id.ints, 0, 12);
			if (right_id_pos == std::string::npos)
			{
				right_id_pos = data.find(right_id.toString());
			}
			if (left_id_pos != std::string::npos && right_id_pos != std::string::npos)
			{
				if (left_id_pos < right_id_pos)
				{
					left_ip = addr.ip.getV4();
					left_port = addr.port;
					std::cout << addr.toString() << " - " << left_id.toString() << " on proxy port " << Endianness::toNative(port) << std::endl;
				}
				else
				{
					right_ip = addr.ip.getV4();
					right_port = addr.port;
					std::cout << addr.toString() << " - " << right_id.toString() << " on proxy port " << Endianness::toNative(port) << std::endl;
				}
			}
			else if (left_id_pos != std::string::npos)
			{
				left_ip = addr.ip.getV4();
				left_port = addr.port;
				std::cout << addr.toString() << " - " << left_id.toString() << " on proxy port " << Endianness::toNative(port) << std::endl;
			}
			else if (right_id_pos != std::string::npos)
			{
				right_ip = addr.ip.getV4();
				right_port = addr.port;
				std::cout << addr.toString() << " - " << right_id.toString() << " on proxy port " << Endianness::toNative(port) << std::endl;
			}
			else if ((addr.ip.getV4() == left_ip && addr.port == left_port) || (addr.ip.getV4() == right_ip && addr.port == right_port))
			{
				// Can't route this traffic just yet
			}
			else
			{
#if PROXYING_FOR_LEGACY
				if (left_port != 0 || right_port != 0)
				{
					if (left_port == 0)
					{
						left_ip = addr.ip.getV4();
						left_port = addr.port;
						std::cout << addr.toString() << " - Assuming that's " << left_id.toString() << " on proxy port " << Endianness::toNative(port) << std::endl;
					}
					else
					{
						right_ip = addr.ip.getV4();
						right_port = addr.port;
						std::cout << addr.toString() << " - Assuming that's " << right_id.toString() << " on proxy port " << Endianness::toNative(port) << std::endl;
					}
				}
				else
#endif
				{
					std::cout << addr.toString() << " - Unexpected traffic on proxy port " << Endianness::toNative(port) << ": " << string::bin2hex(data) << std::endl;
				}
			}
			if (left_port == 0 || right_port == 0) // Still setup phase?
			{
				return;
			}
		}

		if (addr.ip.getV4() == left_ip && addr.port == left_port)
		{
			last_traffic = time::unixSeconds();
			s.udpServerSend(SocketAddr(right_ip, right_port), std::move(data));
		}
		else if (addr.ip.getV4() == right_ip && addr.port == right_port)
		{
			last_traffic = time::unixSeconds();
			s.udpServerSend(SocketAddr(left_ip, left_port), std::move(data));
		}
		else
		{
			std::cout << addr.toString() << " - Unexpected traffic on proxy port " << Endianness::toNative(port) << ": " << string::bin2hex(data) << std::endl;
		}
	}

	bool isActive() const noexcept
	{
		return time::unixSecondsSince(last_traffic) <= 7;
	}
};
static Proxy proxies[MAX_PROXY_CONNECTIONS];

static network_u16_t get_proxy(const MongoId& left_id, bool left_is_server, const MongoId& right_id, bool right_is_server)
{
	if (left_id == right_id)
	{
		return 0;
	}
	for (auto& proxy : proxies)
	{
		if (proxy.left_id == left_id && proxy.right_id == right_id && proxy.left_is_server == left_is_server && proxy.right_is_server == right_is_server
			&& proxy.isActive()
			)
		{
			proxy.last_traffic = time::unixSeconds();
			return proxy.port;
		}
	}
	return 0;
}

static network_u16_t setup_proxying(const MongoId& left_id, bool left_is_server, const MongoId& right_id, bool right_is_server)
{
	if (left_id == right_id)
	{
		return 0;
	}
	size_t num_free_proxies = 0;
	Proxy* free_proxy = nullptr;
	for (auto& proxy : proxies)
	{
		if (proxy.left_id == left_id && proxy.right_id == right_id && proxy.left_is_server == left_is_server && proxy.right_is_server == right_is_server)
		{
			proxy.last_traffic = time::unixSeconds();
			return proxy.port;
		}
		if (!proxy.isActive())
		{
			++num_free_proxies;
			if (free_proxy == nullptr || soup::rand.one_in(num_free_proxies))
			{
				free_proxy = &proxy;
			}
		}
	}
	if (free_proxy)
	{
		// Claim proxy
		free_proxy->left_id = left_id;
		free_proxy->right_id = right_id;
		free_proxy->left_is_server = left_is_server;
		free_proxy->right_is_server = right_is_server;
		free_proxy->last_traffic = time::unixSeconds();

		// Reset proxy to setup phase
		free_proxy->left_port = 0;
		free_proxy->right_port = 0;

		return free_proxy->port;
	}
	return 0;
}
#endif

#if REQUEST_INTRODUCTION
static native_u16_t introduction_port;
#endif

int entry(std::vector<std::string>&& args, bool console)
{
	if (args.size() < 2)
	{
		std::cout << "Syntax: warframe-nrs-server <deployment type>" << std::endl;
		std::cout << "See README.md for details" << std::endl;
		return 1;
	}

#if USE_DTLSBRIDGE
	init();
#endif

	Server serv;

	ServerServiceUdp srv([](Socket& s, SocketAddr&& addr, std::string&& data, ServerServiceUdp&)
	{
#if ENABLE_HTTP || MULTI_NRS
		if (!nrs_socket)
		{
			nrs_socket = Scheduler::get()->getShared(s);
		}
#endif

		bool is_dtls = false;
#if USE_DTLSBRIDGE
		{
			std::string data_copy = data;
			uint8_t pendingSend[4096];
			uint8_t decryptedData[4096];
			size_t pendingSendLength = 0;
			size_t decryptedDataLength = 0;
			std::string endpoint = addr.toString();
			is_dtls = ReadData((uint8_t*)data_copy.data(), data_copy.size(), pendingSend, &pendingSendLength, decryptedData, &decryptedDataLength, endpoint.c_str());
			if (pendingSendLength > 0)
			{
				s.udpServerSend(addr, (const char*)pendingSend, pendingSendLength);
			}
			if (decryptedDataLength != 0)
			{
				const uint8_t AESkey[] = { 0x63, 0x8C, 0x59, 0x2C, 0xE1, 0x57, 0xC2, 0x1B };
				if (decryptedDataLength == sizeof(AESkey) && memcmp(decryptedData, AESkey, sizeof(AESkey)) == 0)
				{
					uint8_t encryptedData[4096];
					size_t encryptedDataLength = 0;
					WriteData(AESkey, sizeof(AESkey), encryptedData, &encryptedDataLength, endpoint.c_str());
					if (encryptedDataLength > 0)
					{
						s.udpServerSend(addr, (const char*)encryptedData, encryptedDataLength);
					}
					//std::cout << addr.toString() << " - Sent AES key" << std::endl;
					return;
				}
				data = std::string((const char*)decryptedData, decryptedDataLength);
			}
			else if (is_dtls)
			{
				return;
			}
		}
#endif

		MemoryRefReader sr(data);
		SOUP_IF_UNLIKELY (!unpackData(addr, sr, data))
		{
			return;
		}

		//std::cout << addr.toString() << " > " << string::bin2hex(data) << std::endl;

		uint32_t chksum;
		sr.u32_be(chksum);
		//std::cout << "Recvd chksum: " << chksum << std::endl;

		uint32_t initial = crc32c::hash((const uint8_t*)data.data() + sr.getPosition(), data.size() - sr.getPosition(), 0);
		std::string_view salt = "b471e49539930dc9b5a131e6247c7387H"; // >= U41
		if (crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
		{
			salt = "b471e49539930dc9b5a131e6247c7387G"; // < U41 && >= U35.5
			if (crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
			{
				salt = "b471e49539930dc9b5a131e6247c7387F"; // < U35.5 && >= U33
				if (crc32c::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
				{
					initial = crc32::hash((const uint8_t*)data.data() + sr.getPosition(), data.size() - sr.getPosition(), 0);
					salt = "b471e49539930dc9b5a131e6247c7387E"; // < U33 && >= U28
					if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
					{
						salt = "b471e49539930dc9b5a131e6247c7387D"; // < U28 && >= U27
						if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
						{
							salt = "b471e49539930dc9b5a131e6247c7387B"; // < U27 && >= U23
							if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
							{
								salt = "b471e49539930dc9b5a131e6247c7387A"; // < U23 && >= U18.18
								if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
								{
									salt = "6f7fd17e0eb641abQ"; // < U18.18 && >= U16.5
									if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
									{
										salt = "6f7fd17e0eb641abP"; // < U16.5 && >= U16
										if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
										{
											salt = "6f7fd17e0eb641abN"; // < U16 && >= U15.14
											if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
											{
												salt = "6f7fd17e0eb641abH"; // < U15.14 && >= U15
												if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
												{
													salt = "6f7fd17e0eb641abF"; // < U15 && >= U13.4
													if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
													{
														salt = "6f7fd17e0eb641abE"; // < U13.4 && >= U13
														if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
														{
															salt = "6f7fd17e0eb641abD"; // < U13 && >= U12
															if (crc32::hash((const uint8_t*)salt.data(), salt.size(), initial) != chksum)
															{
																chksum = Endianness::invert(chksum);
																uint32_t chksum_hi;
																sr.u32_le(chksum_hi);
																uint64_t chksum64 = (static_cast<uint64_t>(chksum_hi) << 32) | chksum;
																//std::cout << "chksum64 = " << std::hex << chksum64 << std::dec << std::endl;
																salt = "6f7fd17e0eb641abC"; // < U12 && >= U11
																if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
																{
																	salt = "6f7fd17e0eb641ab7"; // < U11 && >= U10.8
																	if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
																	{
																		salt = "6f7fd17e0eb641ab6"; // < U10.8 && >= U8.3
																		if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
																		{
																			salt = "3bd61b742870d0bb3"; // < U8.3
																			if (md5_checksum(data.data() + sr.getPosition(), data.size() - sr.getPosition(), salt) != chksum64)
																			{
																				std::cout << addr.toString() << " - Checksum mismatch: " << string::bin2hex(data) << std::endl;
																				return;
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		//std::cout << addr.toString() << " - salt = " << salt << std::endl;

		uint8_t packet_id;
		sr.u8(packet_id);
		switch (packet_id)
		{
		case 0x54: // Test from client
		case 0x74: // Test from server
			{
				//std::cout << addr.toString() << " - Test: " << string::bin2hex(data) << std::endl;

				C2STest test;
				bool has_timestamp = false;
				uint8_t task_id;

				if (!is_u10_or_below(salt)) // >= U11
				{
					if (!is_u27_or_below(salt)) // >= U28
					{
						if (!is_u32_or_below(salt)) // >= U33
						{
							has_timestamp = true;
							test.acctId.io(sr);
							sr.u64_le(test.timestamp);
							if (sr.getPosition() + 1 == data.size()) // >= U42
							{
								return;
							}
							else
							{
								sr.u32_be(test.local_ip);
								sr.u16_le(test.local_port);
								ser_str(sr, salt, test.local_addr_str);
							}
						}
						else
						{
							const auto pos = sr.getPosition();
							if (test.readU30U31(sr))
							{
								//std::cout << addr.toString() << " - Test format: U30-U31" << std::endl;
								has_timestamp = true;
							}
							else if (sr.seek(pos), test.readU28U29(sr))
							{
								//std::cout << addr.toString() << " - Test format: U28-U29" << std::endl;
							}
							else
							{
								std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
								return;
							}
						}
					}
					else
					{
						test.readU11U27(sr, salt);
					}
				}
				else
				{
					// ',' acctId ',' NatHash
				}

				//std::cout << addr.toString() << " - local_addr: " << IpAddr((native_u32_t)test.local_ip).toString() << ":" << test.local_port << std::endl;
				if (!is_u15_or_below(salt)) // >= U15.14
				{
					//std::cout << addr.toString() << " - local_addr_str: " << test.local_addr_str << std::endl;
				}

				uint32_t reflexive_ip = addr.ip.getV4NativeEndian();
				uint16_t reflexive_port = addr.getPort();

				if (!is_u12_or_below(salt)) // U12 does not expect the public address to be xored in the response
				{
					reflexive_ip ^= 0xAAAAAAAA;
					reflexive_port ^= 0xAAAA;
				}

				StringWriter sw;
				if (!is_u10_or_below(salt)) // >= U11
				{
					{ uint8_t b = 0x64 /* 25 << 2 */; sw.u8(b); }
					if (is_u15_14_or_below(salt))
					{
						// local addr is not xored in the request, but is expected to be xored in the response
						test.local_ip ^= 0xAAAAAAAA;
						test.local_port ^= 0xAAAA;
					}
					if (!is_u15_or_below(salt)) // >= U16
					{
						if (!is_u16_or_below(salt))
						{
							uint8_t bindingServerId = THIS_SERVER_ID;
							sw.u8(bindingServerId);
						}
						sw.u8(packet_id);
						test.acctId.io(sw);
						if (has_timestamp)
						{
							sw.u64_le(test.timestamp);
						}
						sw.u32_be(test.local_ip);
						sw.u16_le(test.local_port);
						ser_str(sw, salt, test.local_addr_str);
						sw.u32_be(reflexive_ip);
						sw.u16_le(reflexive_port);
					}
					else
					{
						sw.u32_be(reflexive_ip);
						sw.u16_le(reflexive_port);
						sw.u32_be(test.local_ip);
						sw.u16_le(test.local_port);
					}
				}
				else
				{
					{ uint8_t b = 39 << 2; sw.u8(b); }
					std::string tmp = addr.toString();
					ser_str(sw, salt, tmp);
				}
#if JITTER
				os::sleep(soup::rand.t<unsigned int>(0, 100));
#endif
				udp_send(s, addr, packData(sw.data, salt), is_dtls);
			}
			break;

		case 0x42: // NAT bind for client
		case 0x62: // NAT bind for server
			{
				MongoId acctId;
				std::string NatHash;
				uint32_t local_ip;
				uint16_t local_port;

				if (!is_u10_or_below(salt)) // >= U11
				{
					acctId.io(sr);
					if (is_u12_or_below(salt)) // < U13
					{
						sr.str(64, NatHash);
					}
					sr.u32_be(local_ip);
					sr.u16_le(local_port);
					local_ip ^= 0xAAAAAAAA;
					local_port ^= 0xAAAA;
					if (!is_u32_or_below(salt)) // >= U33 (Not sent in U29, U30, or U31.5)
					{
						sr.skip(2); // 00 01. Thought it might be related to multiple binding servers, but it's not.
					}
				}
				else // < U11
				{
					sr.skip(1); // ','
					std::string acctId_hex;
					sr.str(24, acctId_hex);
					acctId = string::hex2bin(acctId_hex);
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					std::string NatHash_hex;
					sr.str(128, NatHash_hex);
					NatHash = string::hex2bin(NatHash_hex);
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					SocketAddr sa;
					sa.fromString(data.substr(sr.getPosition()));
					local_ip = sa.ip.getV4NativeEndian();
					local_port = sa.getPort();
					sr.seekEnd();
				}

				uint32_t reflexive_ip = addr.ip.getV4NativeEndian();
				uint16_t reflexive_port = addr.getPort();

				AccountData* data;
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					data = &e->second;
				}
				else
				{
					collect_garbage();
#if MULTI_NRS
					broadcast_custom_message("+" + std::string((const char*)acctId.ints, 12));
#endif
					data = &account_map.emplace(acctId, AccountData{}).first->second;
				}
				data->reflexive_ip = reflexive_ip;
				data->local_ip = local_ip;
				data->salt = salt;
				data->is_dtls = is_dtls;
				if (packet_id == 0x42)
				{
					data->reflexive_port_client = reflexive_port;
					data->local_port_client = local_port;
					std::string presence;
					if (!is_u10_or_below(salt)) // >= U11
					{
						sr.u8(data->status);
						if (!is_u15_or_below(salt)) // >= U15.14
						{
							uint8_t num_proxy_connections = 0;
							sr.u8(num_proxy_connections);
							sr.skip(num_proxy_connections * (12 + 1)); // seems to be account id of target followed by 0x00
						}
						ser_str(sr, salt, presence);
					}

					//std::cout << addr.toString() << "#" << acctId.toString() << " - NAT bound for client " << string::bin2hex(acctId) << std::endl;
					//std::cout << addr.toString() << "#" << acctId.toString() << " - Client Local Addr: " << IpAddr((native_u32_t)local_ip).toString() << ":" << local_port << std::endl;
					//std::cout << addr.toString() << "#" << acctId.toString() << " - Status: " << (int)data->status << std::endl;
					if (presence != data->presence)
					{
						data->presence = std::move(presence);
						std::cout << addr.toString() << "#" << acctId.toString() << " - Updated presence: " << data->presence << std::endl;
					}

#if ENABLE_MOTD
					if (!data->sent_motd)
					{
						if (auto motd = string::fromFile("motd.txt"); !motd.empty())
						{
							motd.append(3, '\0');
							data->sendGameInvite(s, acctId, acctId, R"({})", motd, 0);
							data->sent_motd = true;
						}
					}
#endif
				}
				else
				{
					//std::cout << addr.toString() << "#" << acctId.toString() << " - Server Local Addr: " << IpAddr((native_u32_t)local_ip).toString() << ":" << local_port << std::endl;

					data->reflexive_port_server = reflexive_port;
					data->local_port_server = local_port;
				}
				data->last_nat_bind = time::unixSeconds();

				StringWriter sw;
				if (!is_u10_or_below(salt)) // >= U11
				{
					{ uint8_t b = 0x60 /* 24 << 2 */; sw.u8(b); }
					if (!is_u15_or_below(salt))
					{
						{ uint8_t b = (MAX_PROXY_CONNECTIONS > 0 ? 1 : 0); sw.u8(b); } // 0 = no proxying, 1 = yes proxying
						if (!is_u26_or_below(salt)) // 2019.12.13.15.04 (~ U27) and 2022.04.29.12.53 (~ U31.5) crash when this field is not given.
						{
							{ uint8_t b = (packet_id == 0x42 ? 1 : 0); sw.u8(b); }
						}
					}
					if (!is_u12_or_below(salt)) // >= U13
					{
						reflexive_ip ^= 0xAAAAAAAA;
						reflexive_port ^= 0xAAAA;
					}
					sw.u32_be(reflexive_ip);
					sw.u16_le(reflexive_port);
				}
				else
				{
					{ uint8_t b = 37 << 2; sw.u8(b); }
					// U8 does not need anything in the response, but U10.8 needs this:
					std::string tmp = addr.toString();
					ser_str(sw, salt, tmp);
				}
				udp_send(s, addr, packData(sw.data, salt), is_dtls);

				if (data->username.empty())
				{
					if (sr.hasMore()) // U42 + Token
					{
						return;
					}
					else if (!NatHash.empty())
					{
						if (NatHash.substr(0, 4) == "OWF1" && NatHash.back() == '\0')
						{
							data->username = NatHash.c_str() + 4;
						}
					}
				}
#if REQUEST_INTRODUCTION
				if ((data->nat_behaviour == NAT_UNK || data->buildId == 0 || data->username.empty())
					&& data->presence.find("\"hid\":\"" + acctId.toString()) != std::string::npos
					)
				{
					MongoId sender;
					memset(sender.ints, 0x33, 12);
					send_introduction(s, sender, acctId, SocketAddr(this_machine_ip, introduction_port), SocketAddr(data->reflexive_ip, data->reflexive_port_server), IT_FROM_PEER, 69, salt, is_dtls);
				}
#endif
			}
			break;

		case 0x55: // Logout
			{
				MongoId acctId;
				if (!is_u10_or_below(salt)) // >= U11
				{
					acctId.io(sr);
					if (is_u12_or_below(salt)) // < U13
					{
						// NatHash
					}
					else
					{
						if (sr.hasMore())
						{
							std::cout << addr.toString() << " - Logout but there's more: " << string::bin2hex(data) << std::endl;
						}
					}
				}
				else
				{
					sr.skip(1); // ','
					std::string acctId_hex;
					sr.str(24, acctId_hex);
					acctId = string::hex2bin(acctId_hex);
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					//sr.skip(128); // NatHash
				}
#if MULTI_NRS
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					erase_account(e);
				}
#else
				account_map.erase(acctId);
#endif
				std::cout << addr.toString() << "#" << acctId.toString() << " - Logged out" << std::endl;
			}
			break;

		case 0x70: // Fast presence query
		case 0x50: // Rich presence query
			if (!is_u10_or_below(salt)) // >= U11
			{
				/*MongoId acctId;
				acctId.io(sr);*/
				sr.skip(12); // acctId
				if (is_u12_or_below(salt)) // < U13
				{
					sr.skip(64); // NatHash
				}
				uint8_t task_id;
				sr.u8(task_id);
				uint8_t num_queries = 0;
				sr.u8(num_queries);

				StringWriter sw;
				{ uint8_t b = 0x6c; sw.u8(b); }
				sw.u8(task_id);
				{ uint8_t b = (packet_id == 0x50 ? 1 : 0); sw.u8(b); }
				sw.u8(num_queries);
				while (num_queries--)
				{
					MongoId query;
					query.io(sr);
					query.io(sw);
					if (auto e = account_map.find(query); e != account_map.end())
					{
						if (e->second.isActive())
						{
							sw.u8(e->second.status);
							if (packet_id == 0x50)
							{
								ser_str(sw, salt, e->second.presence);
							}
							continue;
						}
						erase_account(e);
					}
#if MULTI_NRS
					if (auto e = remote_account_map.find(query); e != remote_account_map.end())
					{
						uint8_t b = ~e->second; sw.u8(b);
					}
					else
#endif
					{
						uint8_t b = 0; sw.u8(b);
					}
					if (is_u15_14_or_below(salt)) // U27 does not expect this for an offline player, whereas U12 does.
					{
						std::string str;
						ser_str(sw, salt, str);
					}
				}
				udp_send(s, addr, packData(sw.data, salt), is_dtls);

				if (sr.hasMore())
				{
					std::cout << addr.toString() << " - Presence query but there's more: " << string::bin2hex(data) << std::endl;
				}
			}
			else
			{
				// Not used in U8 afaict
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

			// "Resolve pending punchthroughs"
		case 0x52: // Query client addresses
		case 0x72: // Query server addresses
			//std::cout << addr.toString() << " - Request resolve pending punchthroughs" << std::endl;
			if (!is_u10_or_below(salt)) // >= U11
			{
#if MULTI_NRS
				MongoId acctId;
				acctId.io(sr);
#else
				sr.skip(12); // acctId
#endif
				if (is_u12_or_below(salt)) // < U13
				{
					sr.skip(64); // NatHash
				}
				ResolveResponse rr;
				sr.u8(rr.task_id);
				uint8_t num_queries = 0;
				sr.u8(num_queries);
				rr.results.reserve(num_queries);
				while (num_queries--)
				{
					rr.results.emplace_back().account_id.io(sr);
				}
				if (sr.hasMore())
				{
					std::cout << addr.toString() << " - Query addresses but there's more: " << string::bin2hex(data) << std::endl;
				}

				for (auto& r : rr.results)
				{
					//std::cout << addr.toString() << " - Resolving " << r.account_id.toString() << std::endl;
					if (auto e = account_map.find(r.account_id); e != account_map.end())
					{
						if (e->second.isActive())
						{
#if FORCE_PROXY_CONNECTIONS
							r.reflexive_ip = SOUP_IPV4(10, 0, 0, 0);
							r.local_ip = SOUP_IPV4(10, 0, 0, 0);
#else
							r.reflexive_ip = e->second.reflexive_ip;
							r.local_ip = e->second.local_ip;
#endif
							r.reflexive_port = ((packet_id & 0x20) ? e->second.reflexive_port_server : e->second.reflexive_port_client);
							r.local_port = ((packet_id & 0x20) ? e->second.local_port_server : e->second.local_port_client);
							continue;
						}
						erase_account(e);
					}
#if MULTI_NRS
					if (auto e = remote_account_map.find(r.account_id); e != remote_account_map.end())
					{
						r.bindingServerId = e->second;
						r.unresolved = true;
					}
#endif
				}

#if MULTI_NRS
				if (!is_u32_or_below(salt))
				{
					for (auto& r : rr.results)
					{
						if (r.unresolved)
						{
							StringWriter sw;
							sw.u8(packet_id);
							{ uint8_t origin_bindingServerId = THIS_SERVER_ID; sw.u8(origin_bindingServerId); }

							acctId.io(sw);
							{ network_u32_t reply_ip = addr.ip.getV4(); sw.u32_le(reply_ip); }
							{ network_u16_t reply_port = addr.port; sw.u16_le(reply_port); }

							rr.custom_io(sw);
							send_custom_message(r.bindingServerId, std::move(sw.data));
							return;
						}
					}
				}
#endif

				StringWriter sw;
				rr.write(sw, salt);
				udp_send(s, addr, packData(sw.data, salt), is_dtls);
			}
			else
			{
				sr.skip(1); // ','
			#if true
				std::string acctId_hex;
				sr.str(24, acctId_hex);
				std::string acctId = string::hex2bin(acctId_hex);
			#else
				sr.skip(24);
			#endif
				SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
				{
					std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
					return;
				}
				sr.skip(128); // NatHash
				SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
				{
					std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
					return;
				}
				std::string task_id; sr.str(1, task_id);
				sr.skip(1); // ','
				auto arr = string::explode(data.substr(sr.getPosition()), ',');
				std::string res;
				for (const auto& target_hex : arr)
				{
					const MongoId target = string::hex2bin(target_hex);
					res.append(target_hex);
					res.push_back(',');
					if (auto e = account_map.find(target); e != account_map.end())
					{
						if (e->second.isActive())
						{
#if MAX_PROXY_CONNECTIONS > 0 && PROXYING_FOR_LEGACY
							if (auto proxy_port = get_proxy(acctId, false, target, (packet_id & 0x20)))
							{
								res.append(IpAddr(this_machine_ip).toString());
								res.push_back(',');
								res.append(std::to_string(Endianness::toNative(proxy_port)));
							}
							else if (auto proxy_port = get_proxy(target, (packet_id & 0x20), acctId, false))
							{
								res.append(IpAddr(this_machine_ip).toString());
								res.push_back(',');
								res.append(std::to_string(Endianness::toNative(proxy_port)));
							}
							else
#endif
							{
#if FORCE_PROXY_CONNECTIONS
								res.append("10.0.0.0");
#else
								res.append(IpAddr(e->second.reflexive_ip).toString());
#endif
								res.push_back(',');
								res.append(std::to_string((packet_id & 0x20) ? e->second.reflexive_port_server : e->second.reflexive_port_client));
								res.append(",priv,");
#if FORCE_PROXY_CONNECTIONS
								res.append("10.0.0.0");
#else
								res.append(IpAddr(e->second.local_ip).toString());
#endif
								res.push_back(',');
								res.append(std::to_string((packet_id & 0x20) ? e->second.local_port_server : e->second.local_port_client));
							}
							res.push_back(',');
							continue;
						}
						erase_account(e);
					}
					res.append(",0,0,");
				}
				if (!res.empty())
				{
					res.pop_back();
					StringWriter sw;
					{ uint8_t b = 28 << 2; sw.u8(b); }
					ser_str(sw, salt, task_id);
					ser_str(sw, salt, res);
					udp_send(s, addr, packData(sw.data, salt), is_dtls);
				}
			}
			break;

		case 0x43: // Client introduction request
		case 0x49: // Relayed client introduction request
		case 0x63: // Server introduction request
		case 0x69: // Relayed server introduction request
			//std::cout << addr.toString() << " - Introduction request " << string::hex(packet_id) << std::endl;
			{
				MongoId acctId;
				uint8_t task_id;
				MongoId target;

				if (!is_u10_or_below(salt)) // >= U11
				{
					acctId.io(sr);
					if (is_u12_or_below(salt)) // < U13
					{
						sr.skip(64); // NatHash
					}
					sr.u8(task_id);
					target.io(sr);
					if (sr.hasMore())
					{
						std::cout << addr.toString() << " - Introduction request but there's more: " << string::bin2hex(data) << std::endl;
					}
				}
				else
				{
					sr.skip(1); // ','
					std::string acctId_hex;
					sr.str(24, acctId_hex);
					acctId = string::hex2bin(acctId_hex);
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					sr.skip(128); // NatHash
					SOUP_IF_UNLIKELY (char sep = 0; sr.c(sep), sep != ',')
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
					sr.u8(task_id);
					sr.skip(1); // ','
					std::string target_hex;
					sr.str(24, target_hex);
					target = string::hex2bin(target_hex);
					SOUP_IF_UNLIKELY (sr.hasMore())
					{
						std::cout << addr.toString() << " - Malformed packet: " << string::bin2hex(data) << std::endl;
						return;
					}
				}

				native_u32_t local_ip = 0;
				native_u16_t local_port;
				bool from_server = false;
				const bool to_server = (packet_id & 0x20);
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					local_ip = e->second.local_ip;
					from_server = (addr.getPort() == e->second.reflexive_port_server);
					local_port = (from_server ? e->second.local_port_server : e->second.local_port_client);
				}

				if (auto e = account_map.find(target); e != account_map.end())
				{
					if (e->second.isActive())
					{
						SocketAddr to_addr(e->second.reflexive_ip, to_server ? e->second.reflexive_port_server : e->second.reflexive_port_client);
#if FORCE_PROXY_CONNECTIONS
						// For emulation's sake
						send_introduction(s, acctId, target, SocketAddr(SOUP_IPV4_NWE(10, 0, 0, 0), addr.port), to_addr, IT_FROM_PEER, task_id, e->second.salt, e->second.is_dtls);
#else
						if (local_ip)
						{
							// This might not be entirely faithful but sometimes the correct LAN address is not detected, so also trying this the other way around should help.
							send_introduction(s, acctId, target, SocketAddr(local_ip, local_port), to_addr, IT_FROM_PEER, task_id, e->second.salt, e->second.is_dtls);
						}
						send_introduction(s, acctId, target, addr, to_addr, IT_FROM_PEER, task_id, e->second.salt, e->second.is_dtls);
#endif
						std::cout << addr.toString() << "#" << acctId.toString() << " - Introduced to " << to_addr.toString() << "#" << target.toString();
#if MAX_PROXY_CONNECTIONS > 0 && PROXYING_FOR_LEGACY
						if (is_u15_or_below(salt)) // < U15.14
						{
							// Check if other party already reserved a proxy port for us
							network_u16_t proxy_port = get_proxy(target, to_server, acctId, from_server);
							if (proxy_port == 0)
							{
								proxy_port = setup_proxying(acctId, from_server, target, to_server);
							}
							if (proxy_port != 0)
							{
								std::cout << " with proxy port " << Endianness::toNative(proxy_port) << " in reserve";
								send_introduction(s, acctId, target, SocketAddr(this_machine_ip, proxy_port), to_addr, IT_FROM_PEER, task_id, e->second.salt, e->second.is_dtls);
							}
						}
#endif
						std::cout << std::endl;
					}
					else
					{
						erase_account(e);
					}
				}
			}
			break;

#if MAX_PROXY_CONNECTIONS > 0
		case 0x78: // Proxy request
			if (!is_u15_or_below(salt)) // >= U15.14
			{
				MongoId acctId;
				acctId.io(sr);
				uint8_t task_id;
				sr.u8(task_id);
				MongoId target;
				target.io(sr);
				if (sr.hasMore())
				{
					std::cout << addr.toString() << " - Proxy request but there's more: " << string::bin2hex(data) << std::endl;
				}
				//std::cout << addr.toString() << " - Proxy request for " << target.toString() << std::endl;

				if (auto proxy_port = setup_proxying(acctId, false, target, true))
				{
					std::cout << addr.toString() << "#" << acctId.toString() << " - Obtained proxy port " << Endianness::toNative(proxy_port) << " to connect to " << target.toString() << std::endl;
					send_introduction(s, target, acctId, SocketAddr(this_machine_ip, proxy_port), addr, IT_TO_PROXY, task_id, salt, is_dtls);
					if (auto e = account_map.find(target); e != account_map.end())
					{
						if (e->second.isActive())
						{
							send_introduction(s, acctId, target, SocketAddr(this_machine_ip, proxy_port), SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_server), IT_VIA_PROXY, task_id, e->second.salt, e->second.is_dtls);
							break;
						}
						erase_account(e);
					}
#if MULTI_NRS
					if (auto e = remote_account_map.find(target); e != remote_account_map.end())
					{
						StringWriter sw;
						{ char c = 'p'; sw.c(c); }
						acctId.io(sw);
						sw.u8(task_id);
						target.io(sw);
						sw.u32_le(this_machine_ip);
						sw.u16_le(proxy_port);
						send_custom_message(e->second, std::move(sw.data));
						break;
					}
#endif
					std::cout << addr.toString() << "#" << acctId.toString() << " - Could not deliver proxy introduction to " << target.toString() << std::endl;
				}
			}
			else
			{
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;
#endif

		case 0x76: // Game invite
		case 0x79: // Relayed game invite
			if (!is_u10_or_below(salt)) // >= U11 (it is unclear if U11 actually uses this packet because I can't find a way to actually send an invite...)
			{
				MongoId acctId;
				acctId.io(sr);
				if (is_u12_or_below(salt)) // < U13
				{
					sr.skip(64); // NatHash
				}
				uint8_t bindingServerId = THIS_SERVER_ID;
				if (!is_u15_14_or_below(salt))
				{
					sr.u8(bindingServerId);
				}
				if (bindingServerId != THIS_SERVER_ID)
				{
					std::cout << addr.toString() << " - Game invite expected bindingServerId " << THIS_SERVER_ID << " but got " << (int)bindingServerId << std::endl;
				}
				MongoId target;
				target.io(sr);
				uint8_t presence_state;
				sr.u8(presence_state);
				std::string session_info;
				ser_str(sr, salt, session_info);
				std::string inviter_name;
				ser_str(sr, salt, inviter_name);
				std::string unk_str;
				ser_str(sr, salt, unk_str);
				SOUP_UNUSED(unk_str);
				if (auto e = account_map.find(acctId); e != account_map.end())
				{
					if (e->second.username.empty())
					{
						e->second.username = inviter_name;
					}
					else if (e->second.username != inviter_name)
					{
						std::cout << addr.toString() << " - Game invite expected username " << e->second.username << " but got " << inviter_name << std::endl;
						e->second.username = inviter_name;
					}
				}
				if (sr.hasMore())
				{
					std::cout << addr.toString() << " - Game invite but there's more: " << string::bin2hex(data) << std::endl;
				}
				//std::cout << addr.toString() << " - " << inviter_name << " (" << string::bin2hex(acctId) << ") sending invite to " << string::bin2hex(target) << std::endl;
				if (auto e = account_map.find(target); e != account_map.end())
				{
					if (e->second.isActive())
					{
						e->second.sendGameInvite(s, acctId, target, session_info, inviter_name, presence_state, bindingServerId);
						break;
					}
					erase_account(e);
				}
#if MULTI_NRS
				if (auto e = remote_account_map.find(target); e != remote_account_map.end())
				{
					StringWriter sw;
					{ char c = 'i'; sw.c(c); }
					acctId.io(sw);
					target.io(sw);
					sw.str_lp_u64_dyn_b(session_info);
					sw.str_lp_u64_dyn_b(inviter_name);
					sw.u8(presence_state);
					send_custom_message(e->second, std::move(sw.data));
				}
				else
#endif
				if (!is_u15_14_or_below(salt)) // >= U16
				{
					// Send game invite response with status 0 for offline
					StringWriter sw;
					{ uint8_t b = 0xa4; sw.u8(b); }
					acctId.io(sw);
					target.io(sw);
					uint8_t status = 0;
					sw.u8(status);
					udp_send(s, addr, packData(sw.data, salt), is_dtls);
				}
			}
			else
			{
				// Not used in U8 afaict
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

		case 0x56: // Game invite response
			if (!is_u15_14_or_below(salt))
			{
				MongoId acctId;
				acctId.io(sr);
				MongoId target;
				target.io(sr);
				uint8_t status; // 1 = received. 3 = declined. 4 = failed to join.
				sr.u8(status);
				if (sr.hasMore())
				{
					std::cout << addr.toString() << " - Game invite response but there's more: " << string::bin2hex(data) << std::endl;
				}
				if (auto e = account_map.find(target); e != account_map.end())
				{
					if (e->second.isActive())
					{
						StringWriter sw;
						{ uint8_t b = 0xa4; sw.u8(b); }
						target.io(sw);
						acctId.io(sw);
						sw.u8(status);
						udp_send(s, SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_server), packData(sw.data, e->second.salt), e->second.is_dtls);
						break;
					}
					erase_account(e);
				}
#if MULTI_NRS
				/*if (auto e = remote_account_map.find(target); e != remote_account_map.end())
				{
					StringWriter sw;
					{ char c = 'I'; sw.c(c); }
					acctId.io(sw);
					target.io(sw);
					sw.u8(status);
					send_custom_message(e->second, std::move(sw.data));
				}*/
#endif
			}
			else
			{
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

		case 0x6a: // Send social change (when accepting a friend request or removing a friend in U39 and below; done via IRC nowadays)
			if (!is_u11_or_below(salt))
			{
				MongoId acctId; acctId.io(sr);
				uint8_t type; sr.u8(type); // 29 = accept friend request, 30 = remove friend
				uint8_t num_targets = 0; sr.u8(num_targets);
				std::vector<MongoId> targets;
				targets.reserve(num_targets);
				while (num_targets--)
				{
					targets.emplace_back().io(sr);
				}
				std::string json; ser_str(sr, salt, json);

				for (auto& target : targets)
				{
					if (auto e = account_map.find(target); e != account_map.end())
					{
						if (e->second.isActive())
						{
							e->second.sendSocialChange(s, type, json);
							std::cout << addr.toString() << "#" << acctId.toString() << " - Sent social change " << (int)type << " " << json << " to " << SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_client).toString() << "#" << target.toString() << std::endl;
							continue;
						}
						erase_account(e);
					}
#if MULTI_NRS
					if (auto e = remote_account_map.find(target); e != remote_account_map.end())
					{
						StringWriter sw;
						sw.u8(packet_id);
						target.io(sw);
						sw.u8(type);
						sw.str_lp_u64_dyn_b(json);
						send_custom_message(e->second, std::move(sw.data));
						std::cout << addr.toString() << "#" << acctId.toString() << " - Sent social change " << (int)type << " " << json << " to " << target.toString() << " on binding server " << (int)e->second << std::endl;
					}
#endif
				}
			}
			else
			{
				// Not used in U11 or below afaict
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

		case 0x73: // Request friend refresh (when sending a friend request in U39 and below; done via IRC nowadays)
			if (!is_u10_or_below(salt)) // >= U11
			{
				MongoId acctId;
				uint8_t unk = 0x05;
				uint8_t num_targets = 1;

				acctId.io(sr);
				if (is_u12_or_below(salt)) // < U13
				{
					sr.skip(64); // NatHash
				}
				else
				{
					sr.u8(unk); // always 0x09 ?
					sr.u8(num_targets);
				}

				while (num_targets--)
				{
					MongoId target; target.io(sr);
					// In U11, the target account id seems to be followed by 0x05 instead of 0x09
					if (auto e = account_map.find(target); e != account_map.end())
					{
						if (e->second.isActive())
						{
							e->second.sendFriendRefresh(s, unk);
							std::cout << addr.toString() << "#" << acctId.toString() << " - Sent friend request refresh " << (int)unk << " to " << SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_client).toString() << "#" << target.toString() << std::endl;
							continue;
						}
						erase_account(e);
					}
#if MULTI_NRS
					if (auto e = remote_account_map.find(target); e != remote_account_map.end())
					{
						StringWriter sw;
						sw.u8(packet_id);
						target.io(sw);
						sw.u8(unk);
						send_custom_message(e->second, std::move(sw.data));
						std::cout << addr.toString() << "#" << acctId.toString() << " - Sent friend request refresh " << (int)unk << " to " << target.toString() << " on binding server " << (int)e->second << std::endl;
					}
#endif
				}
			}
			else
			{
				// Not used in < U11 afaict
				std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			}
			break;

		case 0x00:
			{
				std::string message = data.substr(sr.getPosition());
				if (message.size() > 3 && message[0] == 0 && message[1] == 0 && (uint8_t)message[2] == (uint8_t)0x80)
				{
					std::cout << addr.toString() << " - Unexpected traffic: " << string::bin2hex(data) << std::endl;
				}
				else
				{
					std::cout << addr.toString() << " - Custom message: " << message << std::endl;
					auto arr = string::explode(message, ',');
					if (arr.size() == 3)
					{
						if (auto e = account_map.find(string::hex2bin(arr[2])); e != account_map.end())
						{
							if (e->second.isActive())
							{
								if (arr[0] == "addPendingFriend")
								{
									e->second.sendFriendRefresh(s, 9);
								}
								else if (arr[0] == "addFriend")
								{
									//e->second.sendSocialChange(s, 29, "{\"id\":\"" + arr[1] + "\",\"avatarImage\":\"\",\"level\":0}");
									//e->second.sendSocialChange(s, 29, "{\"id\":\"" + arr[1] + "\"}");
									e->second.sendFriendRefresh(s, 9); // Unfaithful, but this way the avatarImage and level don't get reset by this notification.
								}
								else if (arr[0] == "removeFriend")
								{
									e->second.sendSocialChange(s, 30, "{\"id\":\"" + arr[1] + "\"}");
								}
							}
							else
							{
								erase_account(e);
							}
						}
					}
				}
			}
			break;

#if MULTI_NRS
		case 0x01: // Custom NRS-to-NRS message
			{
				uint8_t bindingServerId = -1;
				sr.u8(bindingServerId);
				if (bindingServerId < get_servers().size())
				{
					char c; sr.c(c);
					switch (c)
					{
					case '^':
						{
							std::cout << addr.toString() << " - Binding server " << (int)bindingServerId << " has (re)started" << std::endl;

							// Remove any accounts we had associated with this binding server
							for (auto it = remote_account_map.begin(); it != remote_account_map.end(); )
							{
								if (it->second == bindingServerId)
								{
									it = remote_account_map.erase(it);
								}
								else
								{
									++it;
								}
							}

							// Let this binding server know of our accounts
							StringWriter sw;
							{ char c = '+'; sw.c(c); }
							for (auto it = account_map.begin(); it != account_map.end(); ++it)
							{
								const_cast<MongoId&>(it->first).io(sw);
							}
							send_custom_message(bindingServerId, std::move(sw.data));
						}
						break;

					case '+':
						for (MongoId id; id.io(sr); )
						{
							remote_account_map.emplace(id, bindingServerId);
							std::cout << addr.toString() << " - " << id.toString() << " registered on binding server " << (int)bindingServerId << std::endl;
						}
						break;

					case '-':
						{
							MongoId id; id.io(sr);
							remote_account_map.erase(id);
							std::cout << addr.toString() << " - " << id.toString() << " unregistered from binding server " << (int)bindingServerId << std::endl;
						}
						break;

					case 0x52: // Query client addresses
					case 0x72: // Query server addresses
						{
							uint8_t origin_bindingServerId; sr.u8(origin_bindingServerId);
							MongoId acctId; acctId.io(sr);
							network_u32_t reply_ip; sr.u32_le(reply_ip);
							network_u16_t reply_port; sr.u16_le(reply_port);
							ResolveResponse rr; rr.custom_io(sr);

							for (auto& r : rr.results)
							{
								//std::cout << addr.toString() << " - Resolving " << r.account_id.toString() << " for " << acctId.toString() << std::endl;
								if (auto e = account_map.find(r.account_id); e != account_map.end())
								{
									if (e->second.isActive())
									{
#if FORCE_PROXY_CONNECTIONS
										r.reflexive_ip = SOUP_IPV4(10, 0, 0, 0);
										r.local_ip = SOUP_IPV4(10, 0, 0, 0);
#else
										r.reflexive_ip = e->second.reflexive_ip;
										r.local_ip = e->second.local_ip;
#endif
										r.reflexive_port = ((c & 0x20) ? e->second.reflexive_port_server : e->second.reflexive_port_client);
										r.local_port = ((c & 0x20) ? e->second.local_port_server : e->second.local_port_client);
									}
									else
									{
										erase_account(e);
									}
								}
								if (r.bindingServerId == THIS_SERVER_ID)
								{
									r.unresolved = false;
								}
							}

							for (auto& r : rr.results)
							{
								if (r.unresolved)
								{
									StringWriter sw;
									sw.u8(packet_id);
									sw.u8(origin_bindingServerId);

									acctId.io(sw);
									sw.u32_le(reply_ip);
									sw.u16_le(reply_port);

									rr.custom_io(sw);
									if (r.bindingServerId < get_servers().size())
									{
										send_custom_message(r.bindingServerId, std::move(sw.data));
									}
									return;
								}
							}

							StringWriter sw;
							{ char c = '>'; sw.c(c); }
							acctId.io(sw);
							sw.u32_le(reply_ip);
							sw.u16_le(reply_port);
							rr.custom_io(sw);
							if (origin_bindingServerId < get_servers().size())
							{
								send_custom_message(origin_bindingServerId, std::move(sw.data));
							}
						}
						break;

					case '>': // Resolve-results
						{
							MongoId acctId; acctId.io(sr);
							network_u32_t reply_ip; sr.u32_le(reply_ip);
							network_u16_t reply_port; sr.u16_le(reply_port);
							ResolveResponse rr; rr.custom_io(sr);
							if (auto e = account_map.find(acctId); e != account_map.end())
							{
								StringWriter sw;
								rr.write(sw, e->second.salt);
								SocketAddr reply_to(reply_ip, reply_port);
								//std::cout << addr.toString() << " - Got resolve-results for " << reply_to.toString() << "#" << acctId.toString() << std::endl;
								udp_send(s, reply_to, packData(sw.data, e->second.salt), e->second.is_dtls);
							}
						}
						break;

					case 'p':
						{
							MongoId acctId; acctId.io(sr);
							uint8_t task_id; sr.u8(task_id);
							MongoId target; target.io(sr);
							network_u32_t proxy_ip; sr.u32_le(proxy_ip);
							network_u16_t proxy_port; sr.u16_le(proxy_port);
							if (auto e = account_map.find(target); e != account_map.end())
							{
								send_introduction(s, acctId, target, SocketAddr(proxy_ip, proxy_port), SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_server), IT_VIA_PROXY, task_id, e->second.salt, e->second.is_dtls);
							}
						}
						break;

					case 'i':
						{
							MongoId acctId; acctId.io(sr);
							MongoId target; target.io(sr);
							std::string session_info; sr.str_lp_u64_dyn_b(session_info);
							std::string inviter_name; sr.str_lp_u64_dyn_b(inviter_name);
							uint8_t presence_state; sr.u8(presence_state);
							if (auto e = account_map.find(target); e != account_map.end())
							{
								//std::cout << addr.toString() << " - Forward game invite from " << acctId.toString() << " to " << target.toString() << std::endl;
								e->second.sendGameInvite(s, acctId, target, session_info, inviter_name, presence_state, bindingServerId);
							}
						}
						break;

					/*case 'I':
						{
							MongoId acctId; acctId.io(sr);
							MongoId target; target.io(sr);
							uint8_t status; sr.u8(status);
							if (auto e = account_map.find(target); e != account_map.end())
							{
								StringWriter sw;
								{ uint8_t b = 0xa4; sw.u8(b); }
								target.io(sw);
								acctId.io(sw);
								sw.u8(status);
								udp_send(s, SocketAddr(e->second.reflexive_ip, e->second.reflexive_port_server), packData(sw.data, e->second.salt), e->second.is_dtls);
							}
						}
						break;*/

					case 0x6a:
						{
							MongoId target; target.io(sr);
							uint8_t type; sr.u8(type);
							std::string json; sr.str_lp_u64_dyn_b(json);
							if (auto e = account_map.find(target); e != account_map.end())
							{
								e->second.sendSocialChange(s, type, json);
							}
						}
						break;

					case 0x73:
						{
							MongoId target; target.io(sr);
							uint8_t unk; sr.u8(unk);
							if (auto e = account_map.find(target); e != account_map.end())
							{
								e->second.sendFriendRefresh(s, unk);
							}
						}
						break;
					}
				}
			}
			break;
#endif

		default:
			std::cout << addr.toString() << " - Unknown packet with id " << (int)packet_id << ": " << string::bin2hex(data) << std::endl;
			break;
		}
	});

	IpAddr bind_addr;
	if (args[1] == "lan-pc" || args[1] == "lan-server")
	{
		for (const auto& ad : netAdaptor::getAll())
		{
			//if (auto info = dhcp::requestInfo(ad.ip_addr); info.isValid())
	#if SOUP_WINDOWS
			if (ad.name.find("Virtual") == std::string::npos)
	#else
			if (ad.name != "lo")
	#endif
			{
				bind_addr = ad.ip_addr;
				std::cout << "Using " << ad.name << " (" << bind_addr.toString() << ")" << std::endl;
				break;
			}
		}
	}
	else if (args[1] != "public")
	{
		std::cout << "Unknown deployment type: " << args[1] << std::endl;
		std::cout << "See README.md for details" << std::endl;
		return 1;
	}

	std::vector<uint16_t> ports;
	if (args[1] == "lan-pc")
	{
		ports = { 1234 };
#if REQUEST_INTRODUCTION
		introduction_port = 1235;
#endif
	}
	else
	{
		ports = { 4950, 3960 };
#if REQUEST_INTRODUCTION
		introduction_port = 4955;
#endif
	}

	this_machine_ip = bind_addr.getV4();
	if (this_machine_ip == 0)
	{
		auto addr = netInfo::getPublicAddressV4();
		std::cout << "This machine's IP address: " << addr.toString() << std::endl;
		this_machine_ip = addr.getV4();
	}

	for (const uint16_t& port : ports)
	{
		if (!serv.bindUdp(bind_addr, port, &srv))
		{
			std::cout << "Failed to bind UDP/" << port << std::endl;
			return 1;
		}
		std::cout << "Bound UDP/" << port << std::endl;
	}

#if REQUEST_INTRODUCTION
	ServerServiceUdp introduction_srv([](Socket& s, SocketAddr&& addr, std::string&& data, ServerServiceUdp&)
	{
		MemoryRefReader sr(data);
		SOUP_IF_UNLIKELY (!unpackData(addr, sr, data))
		{
			return;
		}

		//std::cout << addr.toString() << " - Traffic on introduction port: " << string::bin2hex(data) << std::endl;

		// P2P introduction
		// 00000080 15 02 74 <taskId> <platformFamily?> <acctId> <str:sessionInfoJson>

		/*size_t pos = data.rfind("{\""); // JSON is not nested afaict, so this should be a good way to find the start.
		if (pos != std::string::npos)
		{
			std::cout << addr.toString() << " - Coaxed into providing more information: " << data.substr(pos) << std::endl;
		}
		else
		{
			// No session info json provided
		}*/

		std::string hostName;
		int64_t buildId = 0;
		if (size_t pos = data.find(R"("hostName":)"); pos != std::string::npos)
		{
			pos += 11;
			if (auto j = json::decode(data.data() + pos, data.size() - pos); j && j->isStr())
			{
				hostName = std::move(j->reinterpretAsStr().value);
			}
		}
		if (size_t pos = data.find(R"("buildId":)"); pos != std::string::npos)
		{
			pos += 10;
			if (auto j = json::decode(data.data() + pos, data.size() - pos); j && j->isInt())
			{
				buildId = j->reinterpretAsInt();
			}
		}
		if (size_t pos = data.find(R"("hostId":)"); pos != std::string::npos)
		{
			pos += 9;
			if (auto j = json::decode(data.data() + pos, data.size() - pos); j && j->isStr())
			{
				std::string hostId = string::hex2bin(j->reinterpretAsStr().value);
				if (auto e = account_map.find(hostId); e != account_map.end())
				{
					e->second.nat_behaviour = (e->second.reflexive_port_server == addr.getPort()) ? NAT_TRANSPARENT : NAT_STRICT;
					if (!hostName.empty())
					{
						// TODO: Sanitise platform suffix so terminal doesn't get polluted?
						//std::cout << addr.toString() << " - Provided username for " << j->reinterpretAsStr().value << ": " << hostName << std::endl;
						e->second.username = std::move(hostName);
					}
					if (buildId != 0)
					{
						e->second.buildId = buildId;
					}
				}
			}
		}
	});
	if (!serv.bindUdp(bind_addr, introduction_port, &introduction_srv))
	{
		std::cout << "Failed to bind UDP/" << introduction_port << std::endl;
		return 1;
	}
	std::cout << "Bound UDP/" << introduction_port << std::endl;
#endif

#if MAX_PROXY_CONNECTIONS > 0
	uint16_t port = 4200;
	for (auto& proxy : proxies)
	{
		while (!serv.bindUdp(bind_addr, port, &proxy))
		{
			port += 3;
		}
		proxy.port = Endianness::toNetwork(port);
		port += 3;
	}
#endif

#if ENABLE_HTTP
	ServerWebService web_srv([](Socket& s, HttpRequest&& req, ServerWebService&)
	{
		if (req.path == "/")
		{
			//ServerWebService::sendHtml(s, string::fromFile("index.html"));
			ServerWebService::sendText(s,
				"Welcome to this deployment of e-nrs!\r\n"
				"\r\n"
				"Available HTTP endpoints:\r\n"
				"- /api/stats\r\n"
				"- /api/me\r\n"
				"- /api/me/accounts\r\n"
				"- /api/account/:id\r\n"
				"- /api/account/:id/proxies (same IP only)\r\n"
				"- /api/session/:id\r\n"
				"- /api/invite/:from/:to\r\n"
			);
		}
		else if (req.path == "/api/stats")
		{
			JsonObject obj;
			std::unordered_map<uint32_t, std::unordered_map<MongoId, uint8_t>> server_session_players;
			{
				uint32_t allocated_accounts = 0;
				uint32_t active_accounts = 0;
				for (auto it = account_map.begin(); it != account_map.end(); ++it)
				{
					++allocated_accounts;
					if (it->second.isActive())
					{
						++active_accounts;
						if (auto pos = it->second.presence.find(R"(":{"id":")"); pos != std::string::npos)
						{
							if (it->second.presence.c_str()[pos + 9] != '"')
							{
								const MongoId sessionId = string::hex2bin(it->second.presence.substr(pos + 9, 24));
								const uint32_t serverId = sessionId.getProcessHash();
								//std::cout << sessionId.toString() << " - " << serverId << std::endl;
								auto server_e = server_session_players.find(serverId);
								if (server_e == server_session_players.end())
								{
									server_e = server_session_players.emplace(serverId, std::unordered_map<MongoId, uint8_t>{}).first;
								}
								if (auto session_e = server_e->second.find(sessionId); session_e != server_e->second.end())
								{
									session_e->second += 1;
								}
								else
								{
									server_e->second.emplace(sessionId, 1);
								}
							}
						}
					}
				}
				obj.add("allocated_accounts", allocated_accounts);
				obj.add("active_accounts", active_accounts);
			}
#if MULTI_NRS
			obj.add("remote_accounts", (intptr_t)remote_account_map.size());
#endif
#if MAX_PROXY_CONNECTIONS > 0
			{
				uint32_t active_proxies = 0;
				for (const auto& proxy : proxies)
				{
					if (proxy.isActive())
					{
						++active_proxies;
					}
				}
				obj.add("active_proxies", active_proxies);
			}
			obj.add("total_proxies", MAX_PROXY_CONNECTIONS);
#endif
			{
				auto servers = soup::make_unique<JsonArray>();
				for (const auto& server : server_session_players)
				{
					auto sessions = soup::make_unique<JsonArray>();
					for (const auto& session : server.second)
					{
						sessions->children.emplace_back(soup::make_unique<JsonInt>(session.second));
					}
					servers->children.emplace_back(std::move(sessions));
				}
				obj.add("server_session_players", std::move(servers));
			}
			ServerWebService::sendText(s, obj.encodePretty());
		}
		else if (req.path == "/api/me")
		{
			ServerWebService::sendText(s, s.peer.ip.toString());
		}
		else if (req.path == "/api/me/accounts")
		{
			const auto reflexive_ip = s.peer.ip.getV4NativeEndian();
			JsonArray arr;
			for (auto it = account_map.begin(); it != account_map.end(); ++it)
			{
				if (it->second.reflexive_ip == reflexive_ip && it->second.isActive())
				{
					arr.children.emplace_back(soup::make_unique<JsonString>(it->first.toString()));
				}
			}
			ServerWebService::sendText(s, arr.encodePretty());
		}
		else if (req.path.substr(0, 13) == "/api/account/")
		{
			const MongoId acctId = string::hex2bin(req.path.substr(13, 24));
			if (auto e = account_map.find(acctId); e != account_map.end())
			{
				if (e->second.isActive())
				{
					if (req.path.size() == 13 + 24)
					{
						JsonObject obj;
						// Data available via NRS
						obj.add("reflexive_ip", e->second.reflexive_ip);
						obj.add("reflexive_port_client", e->second.reflexive_port_client);
						obj.add("reflexive_port_server", e->second.reflexive_port_server);
						obj.add("local_ip", e->second.local_ip);
						obj.add("local_port_client", e->second.local_port_client);
						obj.add("local_port_server", e->second.local_port_server);
						obj.add("status", e->second.status);
						obj.add("presence", e->second.presence);
						// Data available via SNS and conditionally via P2P
						if (e->second.nat_behaviour != NAT_UNK)
						{
							obj.add("strict_nat", e->second.nat_behaviour == NAT_STRICT);
						}
						if (!e->second.username.empty())
						{
							obj.add("username", e->second.username);
						}
						if (e->second.buildId != 0)
						{
							obj.add("buildId", e->second.buildId);
						}
						ServerWebService::sendText(s, obj.encodePretty());
					}
					else if (req.path.substr(13 + 24) == "/proxies")
					{
						if (s.peer.ip.getV4NativeEndian() == e->second.reflexive_ip)
						{
							JsonArray arr;
#if MAX_PROXY_CONNECTIONS > 0
							for (const auto& proxy : proxies)
							{
								if (proxy.isActive() && (proxy.left_id == acctId || proxy.right_id == acctId))
								{
									JsonObject& obj = arr.children.emplace_back(soup::make_unique<JsonObject>())->reinterpretAsObj();
									obj.add("left_id", proxy.left_id.toString());
									obj.add("left_is_server", proxy.left_is_server);
									if (proxy.left_port != 0)
									{
										obj.add("left_ip", Endianness::toNative(proxy.left_ip));
										obj.add("left_port", Endianness::toNative(proxy.left_port));
									}
									obj.add("right_id", proxy.right_id.toString());
									obj.add("right_is_server", proxy.right_is_server);
									if (proxy.right_port != 0)
									{
										obj.add("right_ip", Endianness::toNative(proxy.right_ip));
										obj.add("right_port", Endianness::toNative(proxy.right_port));
									}
									obj.add("port", Endianness::toNative(proxy.port));
									obj.add("last_traffic", proxy.last_traffic);
								}
							}
#endif
							ServerWebService::sendText(s, arr.encodePretty());
						}
						else
						{
							ServerWebService::sendText(s, "request must be sent from the account's IP address");
						}
					}
					else
					{
						ServerWebService::sendText(s, "bad request");
					}
					return;
				}
			}
#if MULTI_NRS
			if (auto e = remote_account_map.find(acctId); e != remote_account_map.end())
			{
				ServerWebService::sendRedirect(s, "http://" + get_servers_for_http()[e->second] + req.path);
				return;
			}
#endif
			ServerWebService::sendText(s, "unknown account id");
		}
		else if (req.path.substr(0, 13) == "/api/session/")
		{
			UniquePtr<JsonNode> obj;
			if (req.path.size() == 13 + 24)
			{
				const std::string sub = R"(":{"id":")" + req.path.substr(13);
				auto peers = soup::make_unique<JsonArray>();
				for (auto it = account_map.begin(); it != account_map.end(); ++it)
				{
					if (it->second.isActive())
					{
						if (size_t pos = it->second.presence.find(sub); pos != std::string::npos)
						{
							if (!obj)
							{
								pos += 2;
								obj = json::decode(it->second.presence.data() + pos, it->second.presence.size() - pos);
								if (obj && !obj->isObj())
								{
									obj.reset();
								}
							}
							peers->children.emplace_back(soup::make_unique<JsonString>(it->first.toString()));
						}
					}
				}
				if (obj)
				{
					obj->reinterpretAsObj().add("_players", std::move(peers));
					ServerWebService::sendText(s, obj->reinterpretAsObj().encodePretty());
					return;
				}
			}
			ServerWebService::sendText(s, "{}");
		}
		else if (req.path.substr(0, 12) == "/api/invite/")
		{
			if (req.path.size() == 12 + 24 + 1 + 24
				&& nrs_socket
				)
			{
				MongoId from_id = string::hex2bin(req.path.substr(12, 24));
				MongoId to_id = string::hex2bin(req.path.substr(12 + 24 + 1));
				if (auto from_e = account_map.find(from_id); from_e != account_map.end())
				{
					if (!from_e->second.presence.empty())
					{
						std::string username = from_id.toString();
						if (!from_e->second.username.empty())
						{
							username = from_e->second.username;
						}
						if (auto to_e = account_map.find(to_id); to_e != account_map.end())
						{
							to_e->second.sendGameInvite(*nrs_socket, from_id, to_id, from_e->second.presence, username, from_e->second.status);
							ServerWebService::sendText(s, "true");
							return;
						}
#if MULTI_NRS
						if (auto to_e = remote_account_map.find(to_id); to_e != remote_account_map.end())
						{
							StringWriter sw;
							{ char c = 'i'; sw.c(c); }
							from_id.io(sw);
							to_id.io(sw);
							sw.str_lp_u64_dyn_b(from_e->second.presence);
							sw.str_lp_u64_dyn_b(username);
							sw.u8(from_e->second.status);
							send_custom_message(to_e->second, std::move(sw.data));
							ServerWebService::sendText(s, "true");
							return;
						}
#endif
					}
				}
#if MULTI_NRS
				if (auto e = remote_account_map.find(from_id); e != remote_account_map.end())
				{
					ServerWebService::sendRedirect(s, "http://" + get_servers_for_http()[e->second] + "/api/invite/" + from_id.toString() + "/" + to_id.toString());
					return;
				}
#endif
			}
			ServerWebService::sendText(s, "false");
		}
#if ENABLE_EXIT_ENDPOINT
		else if (req.path == "/api/exit")
		{
			ServerWebService::sendText(s, "ok");
			throw 0;
		}
#endif
		else
		{
			ServerWebService::send404(s);
		}
	});
	for (const uint16_t& port : ports)
	{
		if (serv.bind(bind_addr, port, &web_srv))
		{
			std::cout << "Bound TCP/" << port << " for HTTP" << std::endl;
		}
		else
		{
			std::cout << "Failed to bind TCP/" << port << " for HTTP" << std::endl;
		}
	}
#endif

#if MULTI_NRS
	broadcast_custom_message("^");
#endif

#ifdef DOCKER
	// Ctrl+C not killing your software? According to the professional ChatGPTs hired by Docker Inc, it's not an issue. Why? Because there's a workaround!
	signal(SIGTERM, [](int) { exit(0); });
#endif

#if !ENABLE_EXIT_ENDPOINT
	serv.run();
	SOUP_UNREACHABLE;
#else
	try
	{
		serv.run();
	}
	catch (const int&)
	{
		// Got /api/exit request
	}
  #if USE_DTLSBRIDGE
	deinit();
  #endif
	return 0;
#endif
}

SOUP_MAIN_CLI(entry);
