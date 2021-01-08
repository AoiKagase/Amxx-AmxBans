/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * 
 * AMX Bans - http://www.amxbans.net
 *  Plugin - Core
 * 
 * Copyright (C) 2014  Ryan "YamiKaitou" LeBlanc
 * Copyright (C) 2009, 2010  Thomas Kurz
 * Forked from "Admin Base (SQL)" in AMX Mod X (version 1.8.1)
 * 
 * 
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 *  In addition, as a special exception, the author gives permission to
 *  link the code of this program with the Half-Life Game Engine ("HL
 *  Engine") and Modified Game Libraries ("MODs") developed by Valve,
 *  L.L.C ("Valve"). You must obey the GNU General Public License in all
 *  respects for all of the code used other than the HL Engine and MODs
 *  from Valve. If you modify this file, you may extend this exception
 *  to your version of the file, but you are not obligated to do so. If
 *  you do not wish to do so, delete this exception statement from your
 *  version.
 * 
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define 	PLUGINNAME 		"AMXBans Core"
#define 	PLUGINAUTHOR 	"YamiKaitou, Aoi.Kagase"
new const 	PLUGINVERSION[] = "7.00";

#include <amxmodx>
#include <amxmisc>
#include <sqlx>
#pragma semicolon 1

#define MAX_ERR_LENGTH			512
#define MAX_QUERY_LENGTH		2048
#define MAX_LENGTH				32

#define		ADMIN_LOOKUP	(1<<0)
#define 	ADMIN_NORMAL	(1<<1)
#define 	ADMIN_STEAM		(1<<2)
#define 	ADMIN_IPADDR	(1<<3)
#define 	ADMIN_NAME		(1<<4)

enum DB_CONFIG
{
	DB_HOST = 0,
	DB_USER,
	DB_PASS,
	DB_NAME,
	DB_TYPE,
	DB_PREFIX,
	// DB_TABLE,
}
enum TBL_DATAS
{
	TBL_AMX_ADMINS			= 0,
	TBL_ADMINS_SERVERS		,
	TBL_SERVER_INFO			, 
}
//Database setting
new g_dbConfig[DB_CONFIG][MAX_LENGTH];
new g_tblNames[TBL_DATAS][MAX_LENGTH] = 
{
	"_amxadmins",
	"_admins_servers",
	"_serverinfo",
};

//Database Handles
new Handle:g_dbTaple;
new Handle:g_dbConnect;

new AdminCount;
new g_cmdLoopback[16];
new bool:g_CaseSensitiveName[33];

// pcvars
new g_amx_mode;
new g_amx_password_field[MAX_LENGTH];
new g_amx_default_access[MAX_LENGTH];

//amxbans
new g_ServerAddr[100];
new g_AdminsFromFile;
new g_szAdminNick[33][32];
new g_iAdminUseStaticBantime[33];
new Array:g_AdminNick;
new Array:g_AdminUseStaticBantime;

//multi forward handles
new bool:g_isAdmin[33];
enum MFHANDLE_TYPES 
{
	Amxbans_Sql_Initialized=0,
	Admin_Connect,
	Admin_Disconnect
};
new MFHandle[MFHANDLE_TYPES];

public plugin_init()
{
	register_plugin(PLUGINNAME, PLUGINVERSION, PLUGINAUTHOR);

	register_dictionary	("admin.txt");
	register_dictionary	("common.txt");
	
	bind_pcvar_num		(create_cvar("amx_mode", 				"1"), 			g_amx_mode);
	bind_pcvar_string	(create_cvar("amx_password_field", 		"_pw"), 		g_amx_password_field, 	charsmax(g_amx_password_field));
	bind_pcvar_string	(create_cvar("amx_default_access", 		""), 			g_amx_default_access, 	charsmax(g_amx_default_access));

	create_cvar			("amx_vote_ratio", 		"0.02");
	create_cvar			("amx_vote_time", 		"10");
	create_cvar			("amx_vote_answers", 	"1");
	create_cvar			("amx_vote_delay", 		"60");
	create_cvar			("amx_last_voting", 	"0");
	create_cvar			("amx_show_activity", 	"2");
	create_cvar			("amx_votekick_ratio",	"0.40");
	create_cvar			("amx_voteban_ratio", 	"0.40");
	create_cvar			("amx_votemap_ratio", 	"0.40");

	set_cvar_float		("amx_last_voting", 	0.0);


	register_srvcmd		("amx_sqladmins", 		"adminSql");
// amxbans
	bind_pcvar_string	(create_cvar("amxbans_server_address",	""),			g_ServerAddr, 			charsmax(g_ServerAddr));
	bind_pcvar_num		(create_cvar("amxbans_use_admins_file",	"0"),			g_AdminsFromFile);
	
	g_AdminNick=ArrayCreate(32,32);
	g_AdminUseStaticBantime=ArrayCreate(1,32);
//
	bind_pcvar_string	(create_cvar("amxbans_sql_host", 		"127.0.0.1"),	g_dbConfig[DB_HOST], 	charsmax(g_dbConfig[]));
	bind_pcvar_string	(create_cvar("amxbans_sql_user", 		"root"),		g_dbConfig[DB_USER], 	charsmax(g_dbConfig[]));
	bind_pcvar_string	(create_cvar("amxbans_sql_pass", 		""),			g_dbConfig[DB_PASS], 	charsmax(g_dbConfig[]));
	bind_pcvar_string	(create_cvar("amxbans_sql_db", 			"amxbans"),		g_dbConfig[DB_NAME], 	charsmax(g_dbConfig[]));
	bind_pcvar_string	(create_cvar("amxbans_sql_type", 		"mysql"),		g_dbConfig[DB_TYPE], 	charsmax(g_dbConfig[]));
	bind_pcvar_string	(create_cvar("amxbans_sql_prefix", 		"amxbans"),		g_dbConfig[DB_PREFIX], 	charsmax(g_dbConfig[]));
	// bind_pcvar_string	(create_cvar("amxbans_sql_table", 		"admins"),		g_dbConfig[DB_TABLE],	charsmax(g_dbConfig[]));

	register_concmd("amx_reloadadmins", "cmdReload", ADMIN_CFG);
	//register_concmd("amx_addadmin", "addadminfn", ADMIN_RCON, "<playername|auth> <accessflags> [password] [authtype] - add specified player as an admin to users.ini")

	format(g_cmdLoopback, 15, "amxauth%c%c%c%c", random_num('A', 'Z'), random_num('A', 'Z'), random_num('A', 'Z'), random_num('A', 'Z'));

	register_clcmd(g_cmdLoopback, "ackSignal");

	remove_user_flags(0, read_flags("z"));		// Remove 'user' flag from server rights

	new configsDir[64];
	get_configsdir(configsDir, 63);
	
	server_cmd("exec %s/amxx.cfg", configsDir);	// Execute main configuration file
	server_cmd("exec %s/sql.cfg", configsDir);
	//server_cmd("exec %s/amxbans.cfg", configsDir)

}

public client_connect(id)
{
	g_CaseSensitiveName[id] = false;
}

public plugin_cfg()
{
	//fixx to be sure cfgs are loaded
	create_forwards();
	set_task(0.1,"delayed_plugin_cfg");
}

create_forwards()
{
	MFHandle[Admin_Connect]=CreateMultiForward("amxbans_admin_connect",ET_IGNORE,FP_CELL);
	MFHandle[Admin_Disconnect]=CreateMultiForward("amxbans_admin_disconnect",ET_IGNORE,FP_CELL);
}

public delayed_plugin_cfg()
{
	//check if amxbans plugins are the first plugins and default admin plugins are disabled
	//added for admins who cant read the docs
	if(find_plugin_byfile("admin.amxx") != INVALID_PLUGIN_ID)
	{
		log_amx("[AMXBans] WARNING: admin.amxx plugin running! stopped.");
		pause("acd","admin.amxx");
	}

	if(find_plugin_byfile("admin_sql.amxx") != INVALID_PLUGIN_ID)
	{
		log_amx("[AMXBans] WARNING: admin_sql.amxx plugin running! stopped.");
		pause("acd","admin_sql.amxx");
	}

	if(find_plugin_byfile("amxbans_core.amxx") != 0) 
		log_amx("[AMXBans] WARNING: amxbans_core.amxx should be the fist entry in your plugins.ini!");

	if(find_plugin_byfile("amxbans_main.amxx") != 1) 
		log_amx("[AMXBans] WARNING: amxbans_main.amxx should be the second entry in your plugins.ini!");
		
	if(strlen(g_ServerAddr) < 9)
	{
		new ip[MAX_IP_LENGTH];
		get_user_ip(0, ip, charsmax(ip));
		formatex(g_ServerAddr, charsmax(g_ServerAddr), "%s", ip);
	}

	if(get_cvar_num("amxbans_debug") >= 1) 
		server_print("[AMXBans] plugin_cfg: ip %s / prefix %s", g_ServerAddr, g_dbConfig[DB_PREFIX]);
	
	server_cmd("amx_sqladmins");
	server_exec();

	set_task(6.1, "delayed_load");
}

public delayed_load()
{
	new configFile[128], curMap[64], configDir[128];

	get_configsdir(configDir, sizeof(configDir)-1);
	get_mapname(curMap, sizeof(curMap)-1);

	new i=0;
	
	while (curMap[i] != '_' && curMap[i++] != '^0') {}
	
	if (curMap[i]=='_')
	{
		// this map has a prefix
		curMap[i]='^0';
		formatex(configFile, sizeof(configFile)-1, "%s/maps/prefix_%s.cfg", configDir, curMap);

		if (file_exists(configFile))
		{
			server_cmd("exec %s", configFile);
		}
	}

	get_mapname(curMap, sizeof(curMap)-1);

	
	formatex(configFile, sizeof(configFile)-1, "%s/maps/%s.cfg", configDir, curMap);

	if (file_exists(configFile))
	{
		server_cmd("exec %s", configFile);
	}
	
}

loadSettings(szFilename[])
{
	new File=fopen(szFilename,"r");
	
	if (File)
	{
		new Text	[512];
		new Flags	[32];
		new Access	[32];
		new AuthData[44];
		new Password[32];
		new Name	[32];
		new Static	[2];
		
		while (!feof(File))
		{
			fgets(File,Text,sizeof(Text)-1);
			
			trim(Text);
			
			// comment
			if (Text[0]==';') 
				continue;
			
			Flags[0]=0;
			Access[0]=0;
			AuthData[0]=0;
			Password[0]=0;
			Name[0] = 0;
			Static[0] = 0;
			
			// not enough parameters
			if (parse(Text, AuthData, charsmax(AuthData), Password, charsmax(Password), Access, charsmax(Access), Flags, charsmax(Flags), Name, charsmax(Name), Static, charsmax(Static)) < 2)
				continue;
			
			admins_push(AuthData,Password,read_flags(Access),read_flags(Flags));
			ArrayPushString(g_AdminNick, Name);
			ArrayPushCell(g_AdminUseStaticBantime, str_to_num(Static));
			
			AdminCount++;
		}
		
		fclose(File);
	}

	if (AdminCount == 1)
		server_print("[AMXBans] %L", LANG_SERVER, "LOADED_ADMIN");
	else
		server_print("[AMXBans] %L", LANG_SERVER, "LOADED_ADMINS", AdminCount);
	
	return 1;
}

public adminSql()
{
	new error[128], errno;
	AdminCount = 0;
	admins_flush();

	// File Load.
	if (g_AdminsFromFile)
	{
		//backup to users.ini
		new configsDir[64];

		get_configsdir(configsDir, 63);
		format(configsDir, 63, "%s/users.ini", configsDir);
		loadSettings(configsDir); // Load admins accounts

		new players[32], num, pv;
		new name[32];
		get_players(players, num);
		for (new i=0; i<num; i++)
		{
			pv = players[i];
			get_user_name(pv, name, 31);
			accessUser(pv, name);
		}
		return PLUGIN_HANDLED;
	}

	// DB Load.
	SQL_SetAffinity("mysql");
	g_dbTaple 	= SQL_MakeDbTuple(
		g_dbConfig[DB_HOST],
		g_dbConfig[DB_USER],
		g_dbConfig[DB_PASS],
		g_dbConfig[DB_NAME]
	);
	g_dbConnect = SQL_Connect(g_dbTaple, errno, error, charsmax(error));

	if (g_dbConnect == Empty_Handle)
	{
		server_print("[AMXBans] %L", LANG_SERVER, "SQL_CANT_CON", error);
		return PLUGIN_HANDLED;
	}
	
	ArrayClear(g_AdminNick);
	ArrayClear(g_AdminUseStaticBantime);
	
	new Handle:query;
	
//amxbans	
	new pquery[1024];
	
	formatex(pquery,1023,"SELECT aa.steamid, aa.password, aa.access, aa.flags, aa.nickname, ads.custom_flags,ads.use_static_bantime FROM %s%s as aa, %s%s as ads, %s%s as si WHERE ((ads.admin_id=aa.id) AND (ads.server_id=si.id) AND ((aa.days=0) OR (aa.expired>UNIX_TIMESTAMP(NOW()))) AND (si.address='%s'))", 
			g_dbConfig[DB_PREFIX], 
			g_tblNames[TBL_AMX_ADMINS], 
			g_dbConfig[DB_PREFIX], 
			g_tblNames[TBL_ADMINS_SERVERS], 
			g_dbConfig[DB_PREFIX], 
			g_tblNames[TBL_SERVER_INFO],
			g_ServerAddr);
	
	query = SQL_PrepareQuery(g_dbConnect, pquery);
	
	SQL_Execute(query);
//
	
	if(SQL_NumRows(query))
	{
		/** do this incase people change the query order and forget to modify below */
		new qcolAuth 	= SQL_FieldNameToNum(query, "steamid");
		new qcolPass 	= SQL_FieldNameToNum(query, "password");
		new qcolAccess 	= SQL_FieldNameToNum(query, "access");
		new qcolFlags 	= SQL_FieldNameToNum(query, "flags");
		new qcolNick 	= SQL_FieldNameToNum(query, "nickname");
		new qcolCustom 	= SQL_FieldNameToNum(query, "custom_flags");
		new qcolStatic 	= SQL_FieldNameToNum(query, "use_static_bantime");
	
	
		new AuthData[44];
		new Password[44];
		new Access	[32];
		new Flags	[32];
		new Nick	[32];
		new Static	[5];
		new iStatic;
		
		while (SQL_MoreResults(query))
		{
			SQL_ReadResult(query, qcolAuth, AuthData, sizeof(AuthData)-1);
			SQL_ReadResult(query, qcolPass, Password, sizeof(Password)-1);
			SQL_ReadResult(query, qcolStatic, Static, sizeof(Static)-1);
			SQL_ReadResult(query, qcolCustom, Access, sizeof(Access)-1);
			SQL_ReadResult(query, qcolNick, Nick, sizeof(Nick)-1);
			SQL_ReadResult(query, qcolFlags, Flags, sizeof(Flags)-1);
			
			//if custom access not set get the global
			trim(Access);
			if(equal(Access,"")) SQL_ReadResult(query, qcolAccess, Access, sizeof(Access)-1);
			
			admins_push(AuthData,Password,read_flags(Access),read_flags(Flags));
			
			//save nick
			ArrayPushString(g_AdminNick,Nick);
			
			//save static bantime
			iStatic=1;
			if(equal(Static,"no")) iStatic=0;
			ArrayPushCell(g_AdminUseStaticBantime,iStatic);
			
			++AdminCount;
			SQL_NextRow(query);
		}
	}

	if (AdminCount == 1)
		server_print("[AMXBans] %L", LANG_SERVER, "SQL_LOADED_ADMIN");
	else
		server_print("[AMXBans] %L", LANG_SERVER, "SQL_LOADED_ADMINS", AdminCount);
	
	SQL_FreeHandle(query);
	SQL_FreeHandle(g_dbConnect);
	
	new players[32], num, pv;
	new name[32];
	get_players(players, num);
	for (new i=0; i<num; i++)
	{
		pv = players[i];
		get_user_name(pv, name, 31);
		accessUser(pv, name);
	}
	
	return PLUGIN_HANDLED;
}

public plugin_end()
{
	if(g_dbConnect != Empty_Handle) 
		SQL_FreeHandle(g_dbConnect);
}

public cmdReload(id, level, cid)
{
	if (!cmd_access(id, level, cid, 1))
		return PLUGIN_HANDLED;

	//strip original flags (patch submitted by mrhunt)
	remove_user_flags(0, read_flags("z"));
	
	AdminCount = 0;
	adminSql();

	if (id != 0)
	{
		if (AdminCount == 1)
			console_print(id, "[AMXBans] %L", LANG_SERVER, "SQL_LOADED_ADMIN");
		else
			console_print(id, "[AMXBans] %L", LANG_SERVER, "SQL_LOADED_ADMINS", AdminCount);
	}

	return PLUGIN_HANDLED;
}

getAccess(id, name[], authid[], ip[], password[])
{
	new index = -1;
	new result = 0;
	
	static Count;
	static Flags;
	static Access;
	static AuthData[44];
	static Password[32];
	
	g_CaseSensitiveName[id] = false;

	Count=admins_num();
	for (new i = 0; i < Count; ++i)
	{
		Flags=admins_lookup(i,AdminProp_Flags);
		admins_lookup(i,AdminProp_Auth,AuthData,sizeof(AuthData)-1);
		
		if (Flags & FLAG_AUTHID)
		{
			if (equal(authid, AuthData))
			{
				index = i;
				break;
			}
		}
		else if (Flags & FLAG_IP)
		{
			new c = strlen(AuthData);
			
			if (AuthData[c - 1] == '.')	/* check if this is not a xxx.xxx. format */
			{
				if (equal(AuthData, ip, c))
				{
					index = i;
					break;
				}
			}				/* in other case an IP must just match */
			else if (equal(ip, AuthData))
			{
				index = i;
				break;
			}
		} 
		else 
		{
			if (Flags & FLAG_CASE_SENSITIVE)
			{
				if (Flags & FLAG_TAG)
				{
					if (contain(name, AuthData) != -1)
					{
						index = i;
						g_CaseSensitiveName[id] = true;
						break;
					}
				}
				else if (equal(name, AuthData))
				{
					index = i;
					g_CaseSensitiveName[id] = true;
					break;
				}
			}
			else
			{
				if (Flags & FLAG_TAG)
				{
					if (containi(name, AuthData) != -1)
					{
						index = i;
						break;
					}
				}
				else if (equali(name, AuthData))
				{
					index = i;
					break;
				}
			}
		}
	}

	if (index != -1)
	{
		Access=admins_lookup(index,AdminProp_Access);
//amxbans
		ArrayGetString(g_AdminNick,index,g_szAdminNick[id],31);
		g_iAdminUseStaticBantime[id]=ArrayGetCell(g_AdminUseStaticBantime,index);
//

		if (Flags & FLAG_NOPASS)
		{
			result |= 8;
			new sflags[32];
			
			get_flags(Access, sflags, 31);
			set_user_flags(id, Access);
			
			new ret;
			if(!g_isAdmin[id]) ExecuteForward(MFHandle[Admin_Connect],ret,id);
			g_isAdmin[id]=true;
			
			log_amx("Login: ^"%s<%d><%s><>^" became an admin (account ^"%s^") (access ^"%s^") (address ^"%s^") (nick ^"%s^") (static %d)", \
				name, get_user_userid(id), authid, AuthData, sflags, ip,g_szAdminNick[id],g_iAdminUseStaticBantime[id]);
		}
		else 
		{
		
			admins_lookup(index,AdminProp_Password,Password,sizeof(Password)-1);

			if (equal(password, Password))
			{
				result |= 12;
				set_user_flags(id, Access);
				
				new sflags[32];
				get_flags(Access, sflags, 31);
				
				new ret;
				if(!g_isAdmin[id]) ExecuteForward(MFHandle[Admin_Connect],ret,id);
				g_isAdmin[id]=true;
				
				log_amx("Login: ^"%s<%d><%s><>^" became an admin (account ^"%s^") (access ^"%s^") (address ^"%s^") (nick ^"%s^") (static %d)", \
					name, get_user_userid(id), authid, AuthData, sflags, ip,g_szAdminNick[id],g_iAdminUseStaticBantime[id]);
			} 
			else 
			{
				result |= 1;
				
				if (Flags & FLAG_KICK)
				{
					result |= 2;
					g_isAdmin[id]=false;
					log_amx("Login: ^"%s<%d><%s><>^" kicked due to invalid password (account ^"%s^") (address ^"%s^")", name, get_user_userid(id), authid, AuthData, ip);
				}
			}
		}
	}
	else if (g_amx_mode == 2)
	{
		result |= 2;
	} 
	else 
	{
		if (!strlen(g_amx_default_access))
		{
			copy(g_amx_default_access, 32, "z");
		}
		
		new idefaccess = read_flags(g_amx_default_access);
		
		if (idefaccess)
		{
			result |= 8;
			set_user_flags(id, idefaccess);
		}
	}
	
	return result;
}

accessUser(id, name[] = "")
{
	remove_user_flags(id);
	
	new userip[MAX_IP_LENGTH], userauthid[MAX_AUTHID_LENGTH], password[32], username[MAX_NAME_LENGTH];
	
	get_user_ip(id, userip, charsmax(userip), 1);
	get_user_authid(id, userauthid, charsmax(userauthid));
	
	if (name[0])
		copy(username, 31, name);
	else
		get_user_name(id, username, 31);
	
	get_user_info(id, g_amx_password_field, password, 31);
	
	new result = getAccess(id, username, userauthid, userip, password);
	
	if (result & 1)
		client_cmd(id, "echo ^"* %L^"", id, "INV_PAS");
	
	if (result & 2)
	{
		client_cmd(id, "%s", g_cmdLoopback);
		return PLUGIN_HANDLED;
	}
	
	if (result & 4)
		client_cmd(id, "echo ^"* %L^"", id, "PAS_ACC");
	
	if (result & 8)
		client_cmd(id, "echo ^"* %L^"", id, "PRIV_SET");
	
	return PLUGIN_CONTINUE;
}

public client_infochanged(id)
{
	if (!is_user_connected(id) || !g_amx_mode)
		return PLUGIN_CONTINUE;
	
	new newname[32], oldname[32];
	
	get_user_name(id, oldname, 31);
	get_user_info(id, "name", newname, 31);

	if (g_CaseSensitiveName[id])
	{
		if (!equal(newname, oldname))
		{
			accessUser(id, newname);
		}
	}
	else
	{
		if (!equali(newname, oldname))
		{
			accessUser(id, newname);
		}
	}
	return PLUGIN_CONTINUE;
}

public client_disconnected(id)
{
	if(g_isAdmin[id])
	{
		new ret;
		ExecuteForward(MFHandle[Admin_Disconnect],ret,id);
	}
	g_isAdmin[id]=false;
}

public ackSignal(id)
{
	server_cmd("kick #%d ^"%L^"", get_user_userid(id), id, "NO_ENTRY");
	return PLUGIN_HANDLED;
}

public client_authorized(id)
	return g_amx_mode ? accessUser(id) : PLUGIN_CONTINUE;

public client_putinserver(id)
{
	if (!is_dedicated_server() && id == 1)
		return g_amx_mode ? accessUser(id) : PLUGIN_CONTINUE;
	
	return PLUGIN_CONTINUE;
}

//natives
public plugin_natives()
{
	register_library("AMXBansCore");
	
	register_native("amxbans_get_db_prefix","native_amxbans_get_prefix");
	register_native("amxbans_get_admin_nick","native_amxbans_get_nick");
	register_native("amxbans_get_static_bantime","native_amxbans_static_bantime");
}

public native_amxbans_get_prefix()
{
	new len = get_param(2);
	set_array(1, g_dbConfig[DB_PREFIX], len);
}

public native_amxbans_get_nick()
{
	
	new id = get_param(1);
	new len= get_param(3);
	
	set_array(2,g_szAdminNick[id],len);
}

public native_amxbans_static_bantime()
{
	new id = get_param(1);
	
	if(get_cvar_num("amxbans_debug") >= 3) 
		log_amx("[AMXBans Core] Native static bantime: id: %d | result: %d",id,g_iAdminUseStaticBantime[id]);
	
	return g_iAdminUseStaticBantime[id];
}