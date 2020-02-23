#include "config.h"
#include "module.h"
#include <WinSock2.h>
#include <Windows.h>
#include <netadr.h>
#include <vector>
#include <ImageHlp.h>


typedef enum netsrc_s
{
	NS_CLIENT,
	NS_SERVER,
	NS_MULTICAST
} netsrc_t;


typedef void (*fnNetchan_OutOfBandPrint) (netsrc_t sock, netadr_t adr, char *format, ...);

HMODULE g_hEngineDLL;
std::vector<PDWORD_PTR> g_vecRelocations;
PIMAGE_SECTION_HEADER psech;
PIMAGE_NT_HEADERS pnth;
extern int g_nServerID;

netadr_t *net_from;

typedef void (*fnSV_ConnectClient)();


fnSV_ConnectClient g_pfnSV_ConnectClient;
fnNetchan_OutOfBandPrint g_pfnNetchan_OutOfBandPrint;

bool DataCompare( PUCHAR pData, PUCHAR pMask, const char* pszMask )
{
	for( ; *pszMask; ++pszMask, ++pData, ++pMask )
	{
		if( *pszMask == 'x' && *pData != *pMask )
		{
			return false;
		}
	}

	return ( *pszMask == NULL );
}

PVOID FindPattern(PVOID lpStartAddress, DWORD_PTR dwSize, const char* pSignature, const char* pMask)
{
	for (DWORD_PTR dwIndex = 0; dwIndex < dwSize; dwIndex++)
	{
		if (DataCompare((PUCHAR)lpStartAddress + dwIndex, (PUCHAR)pSignature, pMask))
		{
			return ((PUCHAR)lpStartAddress + dwIndex);
		}
	}
	return NULL;
}

bool InitEngineParser(void)
{
	g_hEngineDLL = GetModuleHandle(TEXT("swds.dll"));

	if( g_hEngineDLL == NULL )
		g_hEngineDLL = GetModuleHandle(TEXT("hw.dll"));

	if( g_hEngineDLL == NULL )
		g_hEngineDLL = GetModuleHandle(TEXT("sw.dll"));

	if( g_hEngineDLL == NULL )
		return false;


	pnth = ImageNtHeader(g_hEngineDLL);

	if( pnth == NULL )
		return false;

	psech = IMAGE_FIRST_SECTION(pnth);


	DWORD_PTR EndOfCode = psech[0].Misc.VirtualSize + psech[0].VirtualAddress + (DWORD_PTR)g_hEngineDLL;

	PIMAGE_DATA_DIRECTORY pdd = &pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if(pdd->VirtualAddress != 0 && pdd->Size != 0)
	{
		DWORD TotalCountBytes = pdd->Size;
		DWORD SizeOfBlock;
		PUSHORT NextOffset;
		ULONG_PTR VA;
		PIMAGE_BASE_RELOCATION pbr = (PIMAGE_BASE_RELOCATION)(pdd->VirtualAddress + (ULONG_PTR)g_hEngineDLL);

		while( TotalCountBytes )
		{
			SizeOfBlock = pbr->SizeOfBlock;
			TotalCountBytes -= SizeOfBlock;
			SizeOfBlock -= sizeof( IMAGE_BASE_RELOCATION );
			SizeOfBlock /= sizeof( USHORT );
			NextOffset = (PUSHORT)((PCHAR)pbr + sizeof( IMAGE_BASE_RELOCATION ));
			VA = (ULONG_PTR)g_hEngineDLL + pbr->VirtualAddress;

			USHORT Offset;
			PUCHAR FixupVA;

			while ( SizeOfBlock-- ) {
				Offset = *NextOffset & (USHORT)0xfff;
				FixupVA = (PUCHAR)(VA + Offset);

				switch ( (*NextOffset) >> 12 ) {
					case IMAGE_REL_BASED_HIGHLOW:
						if((DWORD_PTR)EndOfCode > (DWORD_PTR)FixupVA)
						{
							g_vecRelocations.push_back((PDWORD_PTR)FixupVA);
						}

						break;
					default:
						break;
				}

				++NextOffset;
			}

			pbr = (PIMAGE_BASE_RELOCATION)NextOffset;
		}
	}

	return true;
}

bool FindNetchan_OutOfBandPrint(void)
{
	DWORD_PTR BeginOfData = psech[2].VirtualAddress + (DWORD_PTR)g_hEngineDLL;
	DWORD_PTR EndOfData =BeginOfData + psech[2].Misc.VirtualSize;
	for(size_t i= 0; i< g_vecRelocations.size();i++)
	{
		PUCHAR reloc = (PUCHAR)g_vecRelocations[i];
		reloc--;

		if(reloc[0] == 0x68)
		{
			DWORD_PTR pushdata = *(DWORD_PTR*)&reloc[1];

			if(pushdata > BeginOfData && pushdata < EndOfData)
			{
				if(!strncmp((PCHAR)pushdata, "\"%s<%i><%s><>\" connected, address \"%s\"\n", sizeof("\"%s<%i><%s><>\" connected, address \"%s\"\n")-1))
				{
Do:
					reloc--;
					while(*reloc != 0x68)
						reloc--;

					if(*(reloc - 2) != 0x6a)
						goto Do;


					while(!(reloc[0] == 0x6A && reloc[1] == 0x01))
						reloc++;

					while(!(reloc[0] == 0xe8))
						reloc++;

					DWORD_PTR addr = (DWORD_PTR)&reloc[0] + *(int*)&reloc[1] + 0x5;
					g_pfnNetchan_OutOfBandPrint = (fnNetchan_OutOfBandPrint)addr;
					return true;
				}
			}
		}
	}

	return false;
}

bool hlmaster_set=false;
netadr_t hlmaster_adr;
float g_time;

void GameDLLInit()
{
	struct hostent *h;
	h = gethostbyname("hlmaster.net");
	if(!h)
	{
		RETURN_META(MRES_IGNORED);
	}

	hlmaster_adr.type = NA_IP;
	*(int*)&hlmaster_adr.ip = *(int*)&h->h_addr_list[0];
	hlmaster_adr.port = htons(27010);
	hlmaster_set=true;
}

#define S2M_HEARTBEAT3			'Z'

void StartFrame(void)
{
	char gamedir[32] = {};

	if(hlmaster_set && gpGlobals->time - g_time > 60.0f)
	{
		g_engfuncs.pfnGetGameDir(gamedir);
		g_pfnNetchan_OutOfBandPrint(NS_SERVER, hlmaster_adr, "%c%s%c", S2M_HEARTBEAT3, gamedir, 0);
		g_time = gpGlobals->time;
	}


	RETURN_META(MRES_IGNORED);
}