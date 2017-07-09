// PE_Parse.h: interface for the PE_Parse class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_PE_PARSE_H__4648A0FC_9FD2_423D_9DAF_913E87B1DEDB__INCLUDED_)
#define AFX_PE_PARSE_H__4648A0FC_9FD2_423D_9DAF_913E87B1DEDB__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include "Tools.h"
#include "resource.h"
class PE_Parse  
{
public:
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTHeaders;
	PIMAGE_FILE_HEADER pPEHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
	DWORD filelen;
	LPVOID pFileBuffer;
public:
	PE_Parse(LPSTR PstrPath);
	virtual ~PE_Parse();
	DWORD ParImport2Dlg(HWND hwnd);
	DWORD RVAToFOA(DWORD stRVA,PVOID lpFileBuf);
	DWORD FOAToRVA(DWORD stRVA,PVOID lpFileBuf);
	DWORD ParImportClick(HWND hwnd);
	DWORD ParRelocTree(HWND hwnd);
private:
	LPSTR PstrPath;

private:
	void getHeaders();
	DWORD ReadFileToBuffer(IN LPSTR FilePath,OUT LPVOID* pFileBuffer);
};

#endif // !defined(AFX_PE_PARSE_H__4648A0FC_9FD2_423D_9DAF_913E87B1DEDB__INCLUDED_)
