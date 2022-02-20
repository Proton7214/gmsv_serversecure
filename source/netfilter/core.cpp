#include "core.hpp"
#include "clientmanager.hpp"
#include "baseserver.h"

#include <GarrysMod/Lua/Interface.h>
#include <GarrysMod/InterfacePointers.hpp>
#include <GarrysMod/FunctionPointers.hpp>
#include <GarrysMod/FactoryLoader.hpp>
#include <GarrysMod/Lua/Helpers.hpp>
#include <Platform.hpp>

#include <detouring/hook.hpp>
#include <detouring/classproxy.hpp>

#include <eiface.h>
#include <iserver.h>
#include <filesystem_stdio.h>
#include <threadtools.h>
#include <utlvector.h>
#include <bitbuf.h>
#include <steam/steam_gameserver.h>
#include <game/server/iplayerinfo.h>
#include <checksum_sha1.h>

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <queue>
#include <string>
#include <array>
#include <random>
#include <unordered_set>
#include <stdexcept>
#include <iostream>

#if defined SYSTEM_WINDOWS

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define SERVERSECURE_CALLING_CONVENTION __stdcall

#include <windows.h>
#include <processthreadsapi.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>

typedef int32_t ssize_t;
typedef int32_t recvlen_t;

#elif defined SYSTEM_LINUX

#define SERVERSECURE_CALLING_CONVENTION

#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#elif defined SYSTEM_MACOSX

#define SERVERSECURE_CALLING_CONVENTION

#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

typedef int32_t SOCKET;
typedef size_t recvlen_t;

static const SOCKET INVALID_SOCKET = -1;

#endif

struct netsocket_t
{
	int32_t nPort;
	bool bListening;
	int32_t hUDP;
	int32_t hTCP;
};

namespace netfilter
{
	class Core
	{
	public:
		static std::unique_ptr<Core> Singleton;
		GarrysMod::Lua::ILuaBase* lua;

		struct server_tags_t
		{
			std::string gm;
			std::string gmws;
			std::string gmc;
			std::string loc;
			std::string ver;
		};

		struct reply_info_t
		{
			bool blocked = false;
			std::string server_name;
			std::string map_name;
			std::string game_dir;
			std::string game_desc;
			int32_t appid = 0;
			int32_t num_clients = 0;
			int32_t max_clients = 0;
			int32_t num_fake_clients = 0;
			bool has_password = false;
			bool secure = false;
			std::string game_version;
			int32_t udp_port = 0;
			uint64_t steamid = 0;
			server_tags_t tags;
		};

		struct player_t
		{
			byte index;
			std::string name;
			long score;
			float time;
		};

		struct reply_player_t
		{
			bool blocked = false;
			bool original = false;

			std::vector<player_t> players;
		};

		enum class PacketType
		{
			Invalid = -1,
			Good,
			Info,
			MasterServer,
			Player
		};

		typedef ssize_t(SERVERSECURE_CALLING_CONVENTION* recvfrom_t)(
			SOCKET s,
			void* buf,
			recvlen_t buflen,
			int32_t flags,
			sockaddr* from,
			socklen_t* fromlen
		);

		struct packet_t
		{
			packet_t() :
				address(),
				address_size(sizeof(address))
			{ }

			sockaddr_in address;
			socklen_t address_size;
			std::vector<uint8_t> buffer;
		};

		Core(const char* game_version)
		{
			server = InterfacePointers::Server();
			if (server == nullptr)
				throw std::runtime_error("failed to dereference IServer");

			if (!server_loader.IsValid())
				throw std::runtime_error("unable to get server factory");

			ICvar* icvar = InterfacePointers::Cvar();
			if (icvar != nullptr)
			{
				sv_visiblemaxplayers = icvar->FindVar("sv_visiblemaxplayers");
				sv_location = icvar->FindVar("sv_location");
			}

			if (sv_visiblemaxplayers == nullptr)
				ConColorMsg(Color(255, 255, 0, 255), "[ServerSecure] Failed to get \"sv_visiblemaxplayers\" convar!\n");

			if (sv_location == nullptr)
				ConColorMsg(Color(255, 255, 0, 255), "[ServerSecure] Failed to get \"sv_location\" convar!\n");

			gamedll = InterfacePointers::ServerGameDLL();
			if (gamedll == nullptr)
				throw std::runtime_error("failed to load required IServerGameDLL interface");

			engine_server = InterfacePointers::VEngineServer();
			if (engine_server == nullptr)
				throw std::runtime_error("failed to load required IVEngineServer interface");

			filesystem = InterfacePointers::FileSystem();
			if (filesystem == nullptr)
				throw std::runtime_error("failed to initialize IFileSystem");

			const FunctionPointers::GMOD_GetNetSocket_t GetNetSocket = FunctionPointers::GMOD_GetNetSocket();
			if (GetNetSocket != nullptr)
			{
				const netsocket_t* net_socket = GetNetSocket(1);
				if (net_socket != nullptr)
					game_socket = net_socket->hUDP;
			}

			if (game_socket == INVALID_SOCKET)
				throw std::runtime_error("got an invalid server socket");

			if (!recvfrom_hook.Enable())
				throw std::runtime_error("failed to detour recvfrom");

			BuildStaticInfo(game_version);
		}

		~Core()
		{
			recvfrom_hook.Disable();
		}

		static std::string ConcatenateTags(const server_tags_t& tags)
		{
			std::string strtags;

			if (!tags.gm.empty())
			{
				strtags += "gm:";
				strtags += tags.gm;
			}

			if (!tags.gmws.empty())
			{
				strtags += strtags.empty() ? "gmws:" : " gmws:";
				strtags += tags.gmws;
			}

			if (!tags.gmc.empty())
			{
				strtags += strtags.empty() ? "gmc:" : " gmc:";
				strtags += tags.gmc;
			}

			if (!tags.loc.empty())
			{
				strtags += strtags.empty() ? "loc:" : " loc:";
				strtags += tags.loc;
			}

			if (!tags.ver.empty())
			{
				strtags += strtags.empty() ? "ver:" : " ver:";
				strtags += tags.ver;
			}

			return strtags;
		}

		void BuildStaticInfo(const char* game_version)
		{
			reply_info.game_desc = gamedll->GetGameDescription();

			{
				reply_info.game_dir.resize(256);
				engine_server->GetGameDir(
					&reply_info.game_dir[0],
					static_cast<int32_t>(reply_info.game_dir.size()));
				reply_info.game_dir.resize(std::strlen(reply_info.game_dir.c_str()));

				size_t pos = reply_info.game_dir.find_last_of("\\/");
				if (pos != std::string::npos) {
					reply_info.game_dir.erase(0, pos + 1);
				}
			}

			reply_info.max_clients = server->GetMaxClients();
			reply_info.udp_port = server->GetUDPPort();

			{
				const IGamemodeSystem::Information& gamemode = dynamic_cast<CFileSystem_Stdio*>(filesystem)->Gamemodes()->Active();

				if (!gamemode.name.empty()) {
					reply_info.tags.gm = gamemode.name;
				} else {
					reply_info.tags.gm.clear();
				}

				if (gamemode.workshopid != 0) {
					reply_info.tags.gmws = std::to_string(gamemode.workshopid);
				} else {
					reply_info.tags.gmws.clear();
				}

				if (!gamemode.category.empty()) {
					reply_info.tags.gmc = gamemode.category;
				} else {
					reply_info.tags.gmc.clear();
				}

				if (game_version != nullptr) {
					reply_info.tags.ver = game_version;
				}
			}

			{
				FileHandle_t file = filesystem->Open("steam.inf", "r", "GAME");
				if (file == nullptr) {
					reply_info.game_version = default_game_version;
					DevWarning("[ServerSecure] Error opening steam.inf\n");
					return;
				}

				std::array<char, 256> buff{};
				bool failed = filesystem->ReadLine(buff.data(), buff.size(), file) == nullptr;
				filesystem->Close(file);

				if (failed) {
					reply_info.game_version = default_game_version;
					DevWarning("[ServerSecure] Failed reading steam.inf\n");
					return;
				}

				reply_info.game_version = &buff[13];

				size_t pos = reply_info.game_version.find_first_of("\r\n");
				if (pos != std::string::npos) {
					reply_info.game_version.erase(pos);
				}
			}
		}

		void BuildInfo()
		{
			reply_info.server_name = server->GetName();
			reply_info.map_name = server->GetMapName();
			reply_info.appid = engine_server->GetAppID();
			reply_info.num_clients = server->GetNumClients();
			int32_t max_clients = sv_visiblemaxplayers != nullptr ? sv_visiblemaxplayers->GetInt() : -1;

			if (max_clients <= 0 || max_clients > reply_info.max_clients)
				max_clients = reply_info.max_clients;

			reply_info.max_clients = max_clients;
			reply_info.num_fake_clients = server->GetNumFakeClients();
			reply_info.has_password = server->GetPassword() != nullptr;
			
			if (!gameserver) gameserver = SteamGameServer();

			if (gameserver)
				reply_info.secure = gameserver->BSecure();
			else
				reply_info.secure = false;

			const CSteamID* steamid = engine_server->GetGameServerSteamID();
			reply_info.steamid = steamid != nullptr ? steamid->ConvertToUint64() : 0;

			if (sv_location != nullptr)
				reply_info.tags.loc = sv_location->GetString();
			else
				reply_info.tags.loc.clear();
		}

		void BuildInfoPacket(reply_info_t info)
		{
			const std::string tags = ConcatenateTags(info.tags);
			const bool has_tags = !tags.empty();

			info_cache_packet.Reset();

			info_cache_packet.WriteLong(-1); // connectionless packet header
			info_cache_packet.WriteByte('I'); // packet type is always 'I'
			info_cache_packet.WriteByte(default_proto_version);
			info_cache_packet.WriteString(info.server_name.c_str());
			info_cache_packet.WriteString(info.map_name.c_str());
			info_cache_packet.WriteString(info.game_dir.c_str());
			info_cache_packet.WriteString(info.game_desc.c_str());
			info_cache_packet.WriteShort(info.appid);
			info_cache_packet.WriteByte(info.num_clients);
			info_cache_packet.WriteByte(info.max_clients);
			info_cache_packet.WriteByte(info.num_fake_clients);
			info_cache_packet.WriteByte('d');
			info_cache_packet.WriteByte(operating_system_char);
			info_cache_packet.WriteByte(info.has_password ? 1 : 0);
			info_cache_packet.WriteByte(static_cast<int>(info.secure));
			info_cache_packet.WriteString(info.game_version.c_str());
			// 0x80 - port number is present
			// 0x10 - server steamid is present
			// 0x20 - tags are present
			// 0x01 - game long appid is present
			info_cache_packet.WriteByte(0x80 | 0x10 | (has_tags ? 0x20 : 0x00) | 0x01);
			info_cache_packet.WriteShort(info.udp_port);
			info_cache_packet.WriteLongLong(static_cast<int64_t>(info.steamid));

			if (has_tags) {
				std::string _tags = " ";
				_tags.append(tags);
				info_cache_packet.WriteString(_tags.c_str());
			}

			info_cache_packet.WriteLongLong(info.appid);
		}

		void BuildPlayerPacket(reply_player_t players)
		{
			player_cache_packet.Reset();

			player_cache_packet.WriteLong(-1); // connectionless packet header
			player_cache_packet.WriteByte('D'); // packet type is always 'D'

			int count = players.players.size();
			player_cache_packet.WriteByte(count);

			for (int position = 0; position < count; position++)
			{
				player_t player = players.players[position];

				player_cache_packet.WriteByte(player.index);
				player_cache_packet.WriteString(player.name.c_str());
				player_cache_packet.WriteLong(player.score);
				player_cache_packet.WriteFloat(player.time);
			}
		}

#define LuaPushString(String, Name) \
	lua->PushString(String.c_str()); \
	lua->SetField(-2, Name);

#define LuaPushNumber(Number, Name) \
	lua->PushNumber(Number); \
	lua->SetField(-2, Name);

#define LuaPushBool(Boolean, Name) \
	lua->PushBool(Boolean); \
	lua->SetField(-2, Name);

#define LuaGetString(String, Name) \
	lua->GetField(-1, Name); \
	String = lua->GetString(-1); \
	lua->Pop(1);

#define LuaGetNumber(String, Name, Type) \
	lua->GetField(-1, Name); \
	String = (Type)lua->GetNumber(-1); \
	lua->Pop(1);

#define LuaGetBool(String, Name) \
	lua->GetField(-1, Name); \
	String = lua->GetBool(-1); \
	lua->Pop(1);

		reply_info_t RunInfoHook(const sockaddr_in& from)
		{
			int32_t status = LuaHelpers::PushHookRun(lua, "A2S_INFO");
			if (!status) return reply_info;

			lua->PushString(IPToString(from.sin_addr));
			lua->PushNumber(from.sin_port);
			lua->CreateTable();
			{
				LuaPushString(reply_info.server_name, "name");
				LuaPushString(reply_info.map_name, "map_name");
				LuaPushString(reply_info.game_dir, "game_dir");
				LuaPushString(reply_info.game_desc, "game_desc");
				LuaPushNumber(reply_info.appid, "appid");
				LuaPushNumber(reply_info.num_clients, "players");
				LuaPushNumber(reply_info.max_clients, "maxplayers");
				LuaPushNumber(reply_info.num_fake_clients, "bots");
				LuaPushBool(reply_info.has_password, "password");
				LuaPushBool(reply_info.secure, "secure");
				LuaPushString(reply_info.game_version, "game_version");
				LuaPushNumber(reply_info.udp_port, "port");

				lua->CreateTable();
				{
					LuaPushString(reply_info.tags.gm, "gm");
					LuaPushString(reply_info.tags.gmc, "gmc");
					LuaPushString(reply_info.tags.gmws, "gmws");
					LuaPushString(reply_info.tags.loc, "loc");
					LuaPushString(reply_info.tags.ver, "ver");
				}
				lua->SetField(-2, "tags");
			}

			reply_info_t info = reply_info;

			LuaHelpers::CallHookRun(lua, 3, 1);

			if (lua->IsType(-1, GarrysMod::Lua::Type::Bool))
			{
				info.blocked = !lua->GetBool(-1);
			}
			else if (lua->IsType(-1, GarrysMod::Lua::Type::Table))
			{
				LuaGetString(info.server_name, "name");
				LuaGetString(info.map_name, "map_name");
				LuaGetString(info.game_dir, "game_dir");
				LuaGetString(info.game_desc, "game_desc");
				LuaGetNumber(info.appid, "appid", int32_t);
				LuaGetNumber(info.num_clients, "players", int32_t);
				LuaGetNumber(info.max_clients, "maxplayers", int32_t);
				LuaGetNumber(info.num_fake_clients, "bots", int32_t);
				LuaGetBool(info.has_password, "password");
				LuaGetBool(info.secure, "secure");
				LuaGetString(info.game_version, "game_version");
				LuaGetNumber(info.udp_port, "port", int32_t);

				lua->GetField(-1, "tags");
				{
					LuaGetString(info.tags.gm, "gm");
					LuaGetString(info.tags.gmc, "gmc");
					LuaGetString(info.tags.gmws, "gmws");
					LuaGetString(info.tags.loc, "loc");
					LuaGetString(info.tags.ver, "ver");
				}
				lua->Pop(1);
			}

			lua->Pop(1);

			return info;
		}

		reply_player_t RunPlayerHook(const sockaddr_in& from)
		{
			reply_player_t players;
			players.blocked = false;
			players.original = true;

			int32_t status = LuaHelpers::PushHookRun(lua, "A2S_PLAYER");
			if (!status) return players;

			lua->PushString(IPToString(from.sin_addr));
			lua->PushNumber(from.sin_port);

			LuaHelpers::CallHookRun(lua, 2, 1);

			if (lua->IsType(-1, GarrysMod::Lua::Type::Bool))
			{
				if (!lua->GetBool(-1))
				{
					players.original = false;
					players.blocked = true;
				}
			}
			else if (lua->IsType(-1, GarrysMod::Lua::Type::Table))
			{
				players.original = false;

				int length = lua->ObjLen(-1);
				
				std::vector<player_t> playerList(length);

				for (int position = 0; position < length; position++)
				{
					player_t player;

					lua->PushNumber(position + 1);
					lua->GetTable(-2);
					{
						LuaGetNumber(player.index, "index", int);
						LuaGetString(player.name, "name");
						LuaGetNumber(player.score, "score", long);
						LuaGetNumber(player.time, "time", float);

						playerList.at(position) = player;
					}
					lua->Pop(1);
				}

				players.players = playerList;
			}

			lua->Pop(1);

			return players;
		}

		void SetFirewallWhitelistState(const bool enabled)
		{
			firewall_whitelist_enabled = enabled;
		}

		// Whitelisted IPs bytes need to be in network order (big endian)
		void AddWhitelistIP(const uint32_t address)
		{
			firewall_whitelist.insert(address);
		}

		void RemoveWhitelistIP(const uint32_t address)
		{
			firewall_whitelist.erase(address);
		}

		void ResetWhitelist()
		{
			std::unordered_set<uint32_t>().swap(firewall_whitelist);
		}

		void SetFirewallBlacklistState(const bool enabled)
		{
			firewall_blacklist_enabled = enabled;
		}

		// Blacklisted IPs bytes need to be in network order (big endian)
		void AddBlacklistIP(const uint32_t address)
		{
			firewall_blacklist.insert(address);
		}

		void RemoveBlacklistIP(const uint32_t address)
		{
			firewall_blacklist.erase(address);
		}

		void ResetBlacklist()
		{
			std::unordered_set<uint32_t>().swap(firewall_blacklist);
		}

		void SetPacketValidationState(const bool enabled)
		{
			packet_validation_enabled = enabled;
		}

		void SetInfoCacheState(const bool enabled)
		{
			info_cache_enabled = enabled;
		}

		void SetPlayerCacheState(const bool enabled)
		{
			player_cache_enabled = enabled;
		}

		void SetInfoCacheTime(const uint32_t time)
		{
			info_cache_time = time;
		}

		ClientManager& GetClientManager()
		{
			return client_manager;
		}

#if defined SYSTEM_WINDOWS

		static constexpr char operating_system_char = 'w';

#elif defined SYSTEM_POSIX

		static constexpr char operating_system_char = 'l';

#elif defined SYSTEM_MACOSX

		static constexpr char operating_system_char = 'm';

#endif
		static constexpr char default_game_version[11] = "2020.10.14";
		static constexpr uint8_t default_proto_version = 17;

		// max size needed to contain a steam authentication key (both server and client)
		static constexpr size_t STEAM_KEYSIZE = 2048;

		static constexpr int32_t PROTOCOL_AUTHCERTIFICATE = 0x01; // Connection from client is using a WON authenticated certificate
		static constexpr int32_t PROTOCOL_HASHEDCDKEY = 0x02; // Connection from client is using hashed CD key because WON comm. channel was unreachable
		static constexpr int32_t PROTOCOL_STEAM = 0x03; // Steam certificates
		static constexpr int32_t PROTOCOL_LASTVALID = 0x03; // Last valid protocol

		static constexpr int32_t MAX_RANDOM_RANGE = 0x7FFFFFFFUL;

		IServer* server = nullptr;

		ISteamGameServer* gameserver = nullptr;

		SourceSDK::FactoryLoader icvar_loader = SourceSDK::FactoryLoader("vstdlib");
		ConVar* sv_visiblemaxplayers = nullptr;
		ConVar* sv_location = nullptr;

		SourceSDK::ModuleLoader dedicated_loader = SourceSDK::ModuleLoader("dedicated");
		SourceSDK::FactoryLoader server_loader = SourceSDK::FactoryLoader("server");

#ifdef PLATFORM_WINDOWS

		Detouring::Hook recvfrom_hook = Detouring::Hook("ws2_32", "recvfrom", reinterpret_cast<void*>(recvfrom_detour));

#else

		Detouring::Hook recvfrom_hook = Detouring::Hook("recvfrom", reinterpret_cast<void*>(recvfrom_detour));

#endif

		SOCKET game_socket = INVALID_SOCKET;

		bool packet_validation_enabled = false;

		bool firewall_whitelist_enabled = false;
		std::unordered_set<uint32_t> firewall_whitelist;

		bool firewall_blacklist_enabled = false;
		std::unordered_set<uint32_t> firewall_blacklist;

		bool info_cache_enabled = false;
		reply_info_t reply_info;
		char info_cache_buffer[1200] = { 0 };
		bf_write info_cache_packet = bf_write(info_cache_buffer, sizeof(info_cache_buffer));
		uint32_t info_cache_last_update = 0;
		uint32_t info_cache_time = 5;

		bool player_cache_enabled = false;
		reply_player_t reply_player;
		char player_cache_buffer[1200] = { 0 };
		bf_write player_cache_packet = bf_write(player_cache_buffer, sizeof(player_cache_buffer));

		char temp_cache_buffer[16] = { 0 };
		bf_write temp_cache_packet = bf_write(temp_cache_buffer, sizeof(temp_cache_buffer));

		ClientManager client_manager;

		IServerGameDLL* gamedll = nullptr;
		IVEngineServer* engine_server = nullptr;
		IFileSystem* filesystem = nullptr;

		inline const char* IPToString(const in_addr& addr)
		{
			static char buffer[16] = { };
			const char* str =
				inet_ntop(AF_INET, const_cast<in_addr*>(&addr), buffer, sizeof(buffer));
			if (str == nullptr)
				return "unknown";

			return str;
		}

		bool ValidChallenge(netadr_t& adr, int challengeNr, const sockaddr_in& from)
		{
			static CBaseServer* baseserver = static_cast<CBaseServer*>(InterfacePointers::Server());
			if (!baseserver->CheckChallengeNr(adr, challengeNr)) {
				baseserver->ReplyServerChallenge(adr);

				DevWarning("[ServerSecure] Sent S2C_CHALLENGE to client %s who sent an invalid challenge. (%d was sent).\n", IPToString(from.sin_addr), challengeNr);

				return false;
			}

			return true;
		}

		PacketType SendInfoCache(const sockaddr_in& from, uint32_t time)
		{
			if (time - info_cache_last_update >= info_cache_time)
			{
				BuildInfo();
				info_cache_last_update = time;
			}

			reply_info_t info = RunInfoHook(from);
			if (info.blocked) return PacketType::Invalid;

			BuildInfoPacket(info);

			sendto(
				game_socket,
				reinterpret_cast<char*>(info_cache_packet.GetData()),
				info_cache_packet.GetNumBytesWritten(),
				0,
				reinterpret_cast<const sockaddr*>(&from),
				sizeof(from)
			);

			DevWarning("[ServerSecure] Handled %s info request using cache\n", IPToString(from.sin_addr));

			return PacketType::Invalid; // we've handled it
		}

		PacketType HandleInfoQuery(const sockaddr_in& from, sockaddr& address, bf_read& packet)
		{
			const uint32_t time = static_cast<uint32_t>(Plat_FloatTime());
			if (!client_manager.CheckIPRate(from.sin_addr.s_addr, time))
			{
				DevWarning("[ServerSecure] Client %s hit rate limit\n", IPToString(from.sin_addr));
				return PacketType::Invalid;
			}

			if (info_cache_enabled)
			{
				netadr_t adr;
				adr.SetFromSockadr(&address);

				int challengeNr = -1;

				char nugget[64];
				nugget[0] = 0;

				if (packet.GetNumBytesLeft() >= Q_strlen("Source Engine Query"))
				{
					packet.ReadString(nugget, sizeof(nugget) - 2);
					nugget[sizeof(nugget) - 1] = 0;
				}

				if (packet.GetNumBytesLeft() >= 4)
				{
					challengeNr = packet.ReadLong();
				}

				if (ValidChallenge(adr, challengeNr, from))
				{
					return SendInfoCache(from, time);
				}
				else
				{
					return PacketType::Invalid;
				}
			}

			return PacketType::Good;
		}

		PacketType SendPlayerCache(const sockaddr_in& from, uint32_t time)
		{
			reply_player_t players = RunPlayerHook(from);
			if (players.blocked) return PacketType::Invalid;
			if (players.original) return PacketType::Good;

			BuildPlayerPacket(players);

			sendto(
				game_socket,
				reinterpret_cast<char*>(player_cache_packet.GetData()),
				player_cache_packet.GetNumBytesWritten(),
				0,
				reinterpret_cast<const sockaddr*>(&from),
				sizeof(from)
			);

			DevWarning("[ServerSecure] Handled %s player request using cache\n", IPToString(from.sin_addr));

			return PacketType::Invalid; // we've handled it
		}

		PacketType HandlePlayerQuery(const sockaddr_in& from, sockaddr& address, bf_read& packet)
		{
			const uint32_t time = static_cast<uint32_t>(Plat_FloatTime());
			if (!client_manager.CheckIPRate(from.sin_addr.s_addr, time))
			{
				DevWarning("[ServerSecure] Client %s hit rate limit\n", IPToString(from.sin_addr));
				return PacketType::Invalid;
			}


			if (player_cache_enabled)
			{
				netadr_t adr;
				adr.SetFromSockadr(&address);

				int challengeNr = -1;

				char nugget[64];
				nugget[0] = 0;

				if (packet.GetNumBytesLeft() >= Q_strlen("Source Engine Query"))
				{
					packet.ReadString(nugget, sizeof(nugget) - 2);
					nugget[sizeof(nugget) - 1] = 0;
				}

				if (packet.GetNumBytesLeft() >= 4)
				{
					challengeNr = packet.ReadLong();
				}

				if (ValidChallenge(adr, challengeNr, from))
				{
					return SendPlayerCache(from, time);
				}
				else
				{
					return PacketType::Invalid;
				}
			}

			return PacketType::Good;
		}

		PacketType ClassifyPacket(const uint8_t* data, int32_t len, const sockaddr_in& from, bf_read& packet)
		{
			if (len == 0)
			{
				DevWarning(
					"[ServerSecure] Bad OOB! len: %d from %s\n",
					len,
					IPToString(from.sin_addr)
				);
				return PacketType::Invalid;
			}

			if (len < 5)
				return PacketType::Good;

			const int32_t channel = static_cast<int32_t>(packet.ReadLong());
			if (channel == -2)
			{
				DevWarning(
					"[ServerSecure] Bad OOB! len: %d, channel: 0x%X from %s\n",
					len,
					channel,
					IPToString(from.sin_addr)
				);
				return PacketType::Invalid;
			}

			if (channel != -1)
				return PacketType::Good;

			const uint8_t type = static_cast<uint8_t>(packet.ReadByte());
			if (packet_validation_enabled)
			{
				switch (type)
				{
				case 'W': // server challenge request
				case 's': // master server challenge
					if (len > 100)
					{
						DevWarning(
							"[ServerSecure] [Ws] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
							len,
							channel,
							type,
							IPToString(from.sin_addr)
						);
						return PacketType::Invalid;
					}

					if (len >= 18 && strncmp(reinterpret_cast<const char*>(data + 5), "statusResponse", 14) == 0)
					{
						DevWarning(
							"[ServerSecure] [Ws] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
							len,
							channel,
							type,
							IPToString(from.sin_addr)
						);
						return PacketType::Invalid;
					}

					return PacketType::Good;

				case 'T': // server info request (A2S_INFO)
					if ((len != 25 && len != 29 && len != 1200) || strncmp(reinterpret_cast<const char*>(data + 5), "Source Engine Query", 19) != 0)
					{
						DevWarning(
							"[ServerSecure] [T] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
							len,
							channel,
							type,
							IPToString(from.sin_addr)
						);
						return PacketType::Invalid;
					}

					return PacketType::Info;

				case 'U': // player info request (A2S_PLAYER)
					return PacketType::Player;
				case 'V': // rules request (A2S_RULES)
					if (len != 9 && len != 1200)
					{
						DevWarning(
							"[ServerSecure] [V] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
							len,
							channel,
							type,
							IPToString(from.sin_addr)
						);
						return PacketType::Invalid;
					}

					return PacketType::Good;

				case 'q': // connection handshake init
				case 'k': // steam auth packet
					DevWarning(
						"[ServerSecure] [qk] Good OOB! len: %d, channel: 0x%X, type: %c from %s\n",
						len,
						channel,
						type,
						IPToString(from.sin_addr)
					);
					return PacketType::Good;
				}

				DevWarning(
					"[ServerSecure] [qk] Bad OOB! len: %d, channel: 0x%X, type: %c from %s\n",
					len,
					channel,
					type,
					IPToString(from.sin_addr)
				);
				return PacketType::Invalid;
			}

			return type == 'T' ? PacketType::Info : (type == 'U' ? PacketType::Player : PacketType::Good);
		}

		bool IsAddressAllowed(const sockaddr_in& addr)
		{
			return
				(
					!firewall_whitelist_enabled ||
					firewall_whitelist.find(addr.sin_addr.s_addr) != firewall_whitelist.end()
					) &&
				(
					!firewall_blacklist_enabled ||
					firewall_blacklist.find(addr.sin_addr.s_addr) == firewall_blacklist.end()
					);
		}

		int32_t HandleNetError(int32_t value)
		{
			if (value == -1)

#if defined SYSTEM_WINDOWS

				WSASetLastError(WSAEWOULDBLOCK);

#elif defined SYSTEM_POSIX

				errno = EWOULDBLOCK;

#endif

			return value;
		}

		ssize_t ReceiveAndAnalyzePacket(
			SOCKET s,
			void* buf,
			recvlen_t buflen,
			int32_t flags,
			sockaddr* from,
			socklen_t* fromlen
		)
		{
			auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>();
			if (trampoline == nullptr)
				return -1;

			const ssize_t len = trampoline(s, buf, buflen, flags, from, fromlen);
			if (len == -1)
				return -1;

			const sockaddr_in& infrom = *reinterpret_cast<sockaddr_in*>(from);
			if (!IsAddressAllowed(infrom))
				return -1;

			DevWarning("[ServerSecure] Address %s was allowed\n", IPToString(infrom.sin_addr));

			const uint8_t* buffer = reinterpret_cast<uint8_t*>(buf);
			bf_read packet(buffer, len);

			PacketType type = ClassifyPacket(buffer, len, infrom, packet);
			
			DevWarning("[ServerSecure] Packet %d was classified\n", static_cast<int>(type));

			if (type == PacketType::Info)
				type = HandleInfoQuery(infrom, *from, packet);
			else if (type == PacketType::Player)
				type = HandlePlayerQuery(infrom, *from, packet);

			return type != PacketType::Invalid ? len : -1;
		}

		ssize_t HandleDetour(
			SOCKET s,
			void* buf,
			recvlen_t buflen,
			int32_t flags,
			sockaddr* from,
			socklen_t* fromlen
		)
		{
			if (s != game_socket)
			{
				auto trampoline = recvfrom_hook.GetTrampoline<recvfrom_t>();
				return trampoline != nullptr ? trampoline(s, buf, buflen, flags, from, fromlen) : -1;
			}

			return HandleNetError(ReceiveAndAnalyzePacket(s, buf, buflen, flags, from, fromlen));
		}

		static ssize_t SERVERSECURE_CALLING_CONVENTION recvfrom_detour(
			SOCKET s,
			void* buf,
			recvlen_t buflen,
			int32_t flags,
			sockaddr* from,
			socklen_t* fromlen
		)
		{
			return Singleton->HandleDetour(s, buf, buflen, flags, from, fromlen);
		}
	};

	std::unique_ptr<Core> Core::Singleton;

	LUA_FUNCTION_STATIC( EnableFirewallWhitelist )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		Core::Singleton->SetFirewallWhitelistState( LUA->GetBool( 1 ) );
		return 0;
	}

	// Whitelisted IPs bytes need to be in network order (big endian)
	LUA_FUNCTION_STATIC( AddWhitelistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		Core::Singleton->AddWhitelistIP( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( RemoveWhitelistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		Core::Singleton->RemoveWhitelistIP( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( ResetWhitelist )
	{
		Core::Singleton->ResetWhitelist( );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnableFirewallBlacklist )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		Core::Singleton->SetFirewallBlacklistState( LUA->GetBool( 1 ) );
		return 0;
	}

	// Blacklisted IPs bytes need to be in network order (big endian)
	LUA_FUNCTION_STATIC( AddBlacklistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		Core::Singleton->AddBlacklistIP( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( RemoveBlacklistIP )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		Core::Singleton->RemoveBlacklistIP( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( ResetBlacklist )
	{
		Core::Singleton->ResetBlacklist( );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnablePacketValidation )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		Core::Singleton->SetPacketValidationState( LUA->GetBool( 1 ) );
		return 0;
	}

	LUA_FUNCTION_STATIC(EnableInfoCache)
	{
		LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
		Core::Singleton->SetInfoCacheState(LUA->GetBool(1));
		return 0;
	}

	LUA_FUNCTION_STATIC(EnablePlayerCache)
	{
		LUA->CheckType(1, GarrysMod::Lua::Type::Bool);
		Core::Singleton->SetPlayerCacheState(LUA->GetBool(1));
		return 0;
	}

	LUA_FUNCTION_STATIC( SetInfoCacheTime )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		Core::Singleton->SetInfoCacheTime( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( RefreshInfoCache )
	{
		Core::Singleton->BuildStaticInfo( nullptr );
		Core::Singleton->BuildInfo( );
		return 0;
	}

	LUA_FUNCTION_STATIC( EnableQueryLimiter )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Bool );
		Core::Singleton->GetClientManager( ).SetState( LUA->GetBool( 1 ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetMaxQueriesWindow )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		Core::Singleton->GetClientManager( ).SetMaxQueriesWindow( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetMaxQueriesPerSecond )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		Core::Singleton->GetClientManager( ).SetMaxQueriesPerSecond( static_cast<uint32_t>( LUA->GetNumber( 1 ) ) );
		return 0;
	}

	LUA_FUNCTION_STATIC( SetGlobalMaxQueriesPerSecond )
	{
		LUA->CheckType( 1, GarrysMod::Lua::Type::Number );
		Core::Singleton->GetClientManager( ).SetGlobalMaxQueriesPerSecond(
			static_cast<uint32_t>( LUA->GetNumber( 1 ) )
		);
		return 0;
	}

	class CBaseServerProxy : public Detouring::ClassProxy<CBaseServer, CBaseServerProxy>
	{
	private:
		typedef CBaseServer TargetClass;
		typedef CBaseServerProxy SubstituteClass;

	public:
		CBaseServerProxy( CBaseServer *baseserver )
		{
			Initialize( baseserver );
			Hook( &CBaseServer::CheckChallengeNr, &CBaseServerProxy::CheckChallengeNr );
			Hook( &CBaseServer::GetChallengeNr, &CBaseServerProxy::GetChallengeNr );
		}

		~CBaseServerProxy( )
		{
			UnHook( &CBaseServer::CheckChallengeNr );
			UnHook( &CBaseServer::GetChallengeNr );
		}

		virtual bool CheckChallengeNr( netadr_t &adr, int nChallengeValue )
		{
			// See if the challenge is valid
			// Don't care if it is a local address.
			if( adr.IsLoopback( ) )
				return true;

			// X360TBD: network
			if( IsX360( ) )
				return true;

			UpdateChallengeIfNeeded( );

			m_challenge[4] = adr.GetIPNetworkByteOrder( );

			CSHA1 hasher;
			hasher.Update( reinterpret_cast<uint8_t *>( &m_challenge[0] ), sizeof( uint32_t ) * m_challenge.size( ) );
			hasher.Final( );
			SHADigest_t hash = { 0 };
			hasher.GetHash( hash );
			if( reinterpret_cast<int *>( hash )[0] == nChallengeValue )
				return true;

			// try with the old random nonce
			m_previous_challenge[4] = adr.GetIPNetworkByteOrder( );

			hasher.Reset( );
			hasher.Update( reinterpret_cast<uint8_t *>( &m_previous_challenge[0] ), sizeof( uint32_t ) * m_previous_challenge.size( ) );
			hasher.Final( );
			hasher.GetHash( hash );
			if( reinterpret_cast<int *>( hash )[0] == nChallengeValue )
				return true;

			return false;
		}

		virtual int GetChallengeNr( netadr_t &adr )
		{
			UpdateChallengeIfNeeded( );

			m_challenge[4] = adr.GetIPNetworkByteOrder( );

			CSHA1 hasher;
			hasher.Update( reinterpret_cast<uint8_t *>( &m_challenge[0] ), sizeof( uint32_t ) * m_challenge.size( ) );
			hasher.Final( );
			SHADigest_t hash = { 0 };
			hasher.GetHash( hash );
			return reinterpret_cast<int *>( hash )[0];
		}

		void UpdateChallengeIfNeeded( )
		{
			const double current_time = Plat_FloatTime( );
			if( m_challenge_gen_time >= 0 && current_time < m_challenge_gen_time + CHALLENGE_NONCE_LIFETIME )
				return;

			m_challenge_gen_time = current_time;
			m_previous_challenge.swap( m_challenge );

			m_challenge[0] = m_rng( );
			m_challenge[1] = m_rng( );
			m_challenge[2] = m_rng( );
			m_challenge[3] = m_rng( );
		}

		static std::mt19937 m_rng;
		static double m_challenge_gen_time;
		static std::array<uint32_t, 5> m_previous_challenge;
		static std::array<uint32_t, 5> m_challenge;

		static std::unique_ptr<CBaseServerProxy> Singleton;
	};

	std::mt19937 CBaseServerProxy::m_rng( std::random_device { } ( ) );
	double CBaseServerProxy::m_challenge_gen_time = -1;
	std::array<uint32_t, 5> CBaseServerProxy::m_previous_challenge;
	std::array<uint32_t, 5> CBaseServerProxy::m_challenge;

	std::unique_ptr<CBaseServerProxy> CBaseServerProxy::Singleton;

	void Initialize( GarrysMod::Lua::ILuaBase *LUA )
	{
		LUA->GetField( GarrysMod::Lua::INDEX_GLOBAL, "VERSION" );
		const char *game_version = LUA->CheckString( -1 );

		bool errored = false;
		try
		{
			Core::Singleton = std::make_unique<Core>( game_version );
			Core::Singleton->lua = LUA;
		}
		catch( const std::exception &e )
		{
			errored = true;
			LUA->PushString( e.what( ) );
		}

		if( errored )
			LUA->Error( );

		LUA->Pop( 1 );

		CBaseServer *baseserver = static_cast<CBaseServer *>( InterfacePointers::Server( ) );
		if( baseserver != nullptr )
			CBaseServerProxy::Singleton = std::make_unique<CBaseServerProxy>( baseserver );

		LUA->PushCFunction( EnableFirewallWhitelist );
		LUA->SetField( -2, "EnableFirewallWhitelist" );

		LUA->PushCFunction( AddWhitelistIP );
		LUA->SetField( -2, "AddWhitelistIP" );

		LUA->PushCFunction( RemoveWhitelistIP );
		LUA->SetField( -2, "RemoveWhitelistIP" );

		LUA->PushCFunction( ResetWhitelist );
		LUA->SetField( -2, "ResetWhitelist" );

		LUA->PushCFunction( EnableFirewallBlacklist );
		LUA->SetField( -2, "EnableFirewallBlacklist" );

		LUA->PushCFunction( AddBlacklistIP );
		LUA->SetField( -2, "AddBlacklistIP" );

		LUA->PushCFunction( RemoveBlacklistIP );
		LUA->SetField( -2, "RemoveBlacklistIP" );

		LUA->PushCFunction( ResetBlacklist );
		LUA->SetField( -2, "ResetBlacklist" );

		LUA->PushCFunction( EnablePacketValidation );
		LUA->SetField( -2, "EnablePacketValidation" );

		LUA->PushCFunction(EnableInfoCache);
		LUA->SetField(-2, "EnableInfoCache");

		LUA->PushCFunction(EnablePlayerCache);
		LUA->SetField(-2, "EnablePlayerCache");

		LUA->PushCFunction( SetInfoCacheTime );
		LUA->SetField( -2, "SetInfoCacheTime" );

		LUA->PushCFunction( RefreshInfoCache );
		LUA->SetField( -2, "RefreshInfoCache" );

		LUA->PushCFunction( EnableQueryLimiter );
		LUA->SetField( -2, "EnableQueryLimiter" );

		LUA->PushCFunction( SetMaxQueriesWindow );
		LUA->SetField( -2, "SetMaxQueriesWindow" );

		LUA->PushCFunction( SetMaxQueriesPerSecond );
		LUA->SetField( -2, "SetMaxQueriesPerSecond" );

		LUA->PushCFunction( SetGlobalMaxQueriesPerSecond );
		LUA->SetField( -2, "SetGlobalMaxQueriesPerSecond" );
	}

	void Deinitialize( )
	{
		CBaseServerProxy::Singleton.reset( );
		Core::Singleton.reset( );
	}
}
