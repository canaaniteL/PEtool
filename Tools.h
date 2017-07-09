// Tools.h: interface for the Tools class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_TOOLS_H__C3167AEB_A860_480D_A9E4_304F4BE0F976__INCLUDED_)
#define AFX_TOOLS_H__C3167AEB_A860_480D_A9E4_304F4BE0F976__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
#include <stdio.h>
#include <windows.h>
#include <malloc.h>
#include <commdlg.h>
#include <commctrl.h>
void __cdecl OutputDebugStringF(const char *format, ...);
DWORD WINAPI ThreadProcShell(LPVOID lpParameter);
DWORD CopyFromImageBufferToFileBuffer(IN PVOID pImageBuffer,OUT LPVOID* pNewFileBuffer ,DWORD len);
DWORD CopyFromFileBufferToImageBuffer(IN LPVOID pFileBuffer,OUT LPVOID* pImageBuffer);
//将文件读取到文件缓冲区中
DWORD ReadFileToBuffer(IN LPSTR FilePath,OUT LPVOID* pFileBuffer);
BOOL MemeryToFile(LPVOID pMemBuffer,size_t size,LPSTR lpszFile);
DWORD NumAlign(DWORD num,DWORD align);
BOOL AddSecion(IN LPVOID pFileBuffer,OUT LPVOID* pNewBuffer,IN LPVOID pPEBuffer,DWORD AddSecLen,DWORD len);
#endif // !defined(AFX_TOOLS_H__C3167AEB_A860_480D_A9E4_304F4BE0F976__INCLUDED_)
