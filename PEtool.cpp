// PEtool.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "PE_Parse.h"
#include "Tools.h"
#define FILEPATH_OUT "C://testShell//a.exe"

#pragma comment(lib,"comctl32.lib")	
#include "PSAPI.H"
#pragma comment(lib, "Psapi.lib") 
//主进程的实例
HINSTANCE hInstanceMain;

HWND hListModuleInfo;
HWND hListProcessInfo;

TCHAR szFileName[MAX_PATH];
TCHAR PEFilePATH[MAX_PATH];
TCHAR PEProtectPATH[MAX_PATH];
TCHAR* ShellPath="C://testShell//EXEProtect.exe";
//PE解析结构指针，定义成全局的，其他的窗口也可以使用
PE_Parse* pPE_P;

VOID Init_Parse_PE_Import(HWND hDlg)
{
	LV_COLUMN lv;
	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	HWND hListDllInfo=GetDlgItem(hDlg,IDC_LIST_DLLINFO);
	//设置整行选中
	SendMessage(hListDllInfo,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	//第一列
	lv.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;

	lv.pszText=TEXT("DLL名");
	lv.cx=85;              //列宽
	lv.iSubItem=0;
	SendMessage(hListDllInfo,LVM_INSERTCOLUMN,0,(DWORD)&lv);

	//第二列
	lv.pszText=TEXT("OriginalFirstThunk");
	lv.cx=85;              //列宽
	lv.iSubItem=1;
	SendMessage(hListDllInfo,LVM_INSERTCOLUMN,1,(DWORD)&lv);

	//第3列
	lv.pszText=TEXT("时间戳");
	lv.cx=85;              //列宽
	lv.iSubItem=2;
	SendMessage(hListDllInfo,LVM_INSERTCOLUMN,2,(DWORD)&lv);

	//第4列
	lv.pszText=TEXT("ForwarderChain");
	lv.cx=85;              //列宽
	lv.iSubItem=3;
	SendMessage(hListDllInfo,LVM_INSERTCOLUMN,3,(DWORD)&lv);

	//第5列
	lv.pszText=TEXT("Name");
	lv.cx=85;              //列宽
	lv.iSubItem=4;
	SendMessage(hListDllInfo,LVM_INSERTCOLUMN,4,(DWORD)&lv);

	//第6列
	lv.pszText=TEXT("FirstThunk");
	lv.cx=85;              //列宽
	lv.iSubItem=5;
	SendMessage(hListDllInfo,LVM_INSERTCOLUMN,5,(DWORD)&lv);

	HWND hListDLLAPIInfo=GetDlgItem(hDlg,IDC_LIST_DLL_APINFO);
	//设置整行选中
//	SendMessage(hListDLLAPIInfo,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	//第1列
	lv.pszText=TEXT("Hint");
	lv.cx=85;              //列宽
	lv.iSubItem=0;
	SendMessage(hListDLLAPIInfo,LVM_INSERTCOLUMN,0,(DWORD)&lv);

	//第2列
	lv.pszText=TEXT("ApiName");
	lv.cx=85;              //列宽
	lv.iSubItem=1;
	SendMessage(hListDLLAPIInfo,LVM_INSERTCOLUMN,1,(DWORD)&lv);

	pPE_P->ParImport2Dlg(hDlg);


}
VOID Init_Parse_PE_SECTION(HWND hDlg)
{
	LV_COLUMN lv;
	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hListModuleInfo=GetDlgItem(hDlg,IDC_LIST_SECTION);
	//设置整行选中
	SendMessage(hListModuleInfo,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	//第一列
	lv.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
	lv.pszText=TEXT("节名称");
	lv.cx=85;              //列宽
	lv.iSubItem=0;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,0,(DWORD)&lv);

	//第二列
	lv.pszText=TEXT("内存偏移");
	lv.cx=85;              //列宽
	lv.iSubItem=1;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,1,(DWORD)&lv);

	//第3列
	lv.pszText=TEXT("内存大小");
	lv.cx=85;              //列宽
	lv.iSubItem=2;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,2,(DWORD)&lv);

	//第4列
	lv.pszText=TEXT("文件偏移");
	lv.cx=85;              //列宽
	lv.iSubItem=3;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,3,(DWORD)&lv);

	//第5列
	lv.pszText=TEXT("内存大小");
	lv.cx=85;              //列宽
	lv.iSubItem=4;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,4,(DWORD)&lv);

	//第6列
	lv.pszText=TEXT("节属性");
	lv.cx=85;              //列宽
	lv.iSubItem=5;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,5,(DWORD)&lv);

	//往list里面写入节信息

	LV_ITEM vitem;
	//初始化
	memset(&vitem,0,sizeof(LV_ITEM));
	vitem.mask=LVIF_TEXT;
	DWORD SectionNum=pPE_P->pPEHeader->NumberOfSections;
	for(DWORD i=0;i<SectionNum;i++)
	{
		//获取节的名字
		TCHAR pSecName[10];
		memset(pSecName,0,10);
		sprintf(pSecName,"%s",pPE_P->pSectionHeader[i].Name);
	
		//获取节的内存偏移地址
		TCHAR pSecMisc[10];
		memset(pSecMisc,0,10);
		sprintf(pSecMisc,"%08X",pPE_P->pSectionHeader[i].VirtualAddress);

		//获取节的内存大小
		TCHAR pSecVA[10];
		memset(pSecVA,0,10);
		sprintf(pSecVA,"%08X",pPE_P->pSectionHeader[i].Misc.VirtualSize);

		//获取节的文件偏移地址
		TCHAR pSecFOA[10];
		memset(pSecFOA,0,10);
		sprintf(pSecFOA,"%08X",pPE_P->pSectionHeader[i].PointerToRawData);

		//获取节的文件大小
		TCHAR pSecRawSize[10];
		memset(pSecRawSize,0,10);
		sprintf(pSecRawSize,"%08X",pPE_P->pSectionHeader[i].SizeOfRawData);

		//获取节属性
		TCHAR pSecCharc[10];
		memset(pSecCharc,0,10);
		sprintf(pSecCharc,"%08X",pPE_P->pSectionHeader[i].Characteristics);

		vitem.pszText=pSecName;
		vitem.iItem=0;          //第几行
		vitem.iSubItem=0;           //第几列
		SendMessage(hListModuleInfo,LVM_INSERTITEM,0,(DWORD)&vitem);  //只有第一列是insertitem,后面的都是setitem

		vitem.pszText=pSecMisc;
		vitem.iItem=0;          //第几行
		vitem.iSubItem=1;           //第几列
		SendMessage(hListModuleInfo,LVM_SETITEM,1,(DWORD)&vitem);

		vitem.pszText=pSecVA;
		vitem.iItem=0;          //第几行
		vitem.iSubItem=2;           //第几列
		SendMessage(hListModuleInfo,LVM_SETITEM,2,(DWORD)&vitem);

		vitem.pszText=pSecFOA;
		vitem.iItem=0;          //第几行
		vitem.iSubItem=3;           //第几列
		SendMessage(hListModuleInfo,LVM_SETITEM,3,(DWORD)&vitem);

		vitem.pszText=pSecRawSize;
		vitem.iItem=0;          //第几行
		vitem.iSubItem=4;           //第几列
		SendMessage(hListModuleInfo,LVM_SETITEM,4,(DWORD)&vitem);

		vitem.pszText=pSecCharc;
		vitem.iItem=0;          //第几行
		vitem.iSubItem=5;           //第几列
		SendMessage(hListModuleInfo,LVM_SETITEM,5,(DWORD)&vitem);
	}

}
VOID Init_Parse_PE_Directory(HWND hwnd)
{

	for(DWORD i=0;i<16;i++)
	{
		TCHAR pStr_R[10];
		TCHAR pStr_S[10];
		sprintf(pStr_R,"%08X",pPE_P->pOptionalHeader->DataDirectory[i].VirtualAddress);
		sprintf(pStr_S,"%08X",pPE_P->pOptionalHeader->DataDirectory[i].Size);
		SetWindowText(GetDlgItem(hwnd,IDC_EDIT_DIRECTORY_R_0+i*2),pStr_R);
		SetWindowText(GetDlgItem(hwnd,IDC_EDIT_DIRECTORY_S_0+i*2),pStr_S);
	}
	//pPE_P->~PE_Parse();     这个地方不是让你显式调用的，new出来的也是在堆上面    需要再复习一下虚函数表
}

//资源表处理函数
BOOL CALLBACK PERelocDlgProc(  									
							IN  HWND hwnd,  		
							IN  UINT uMsg,  		
							IN  WPARAM wParam,  		
							IN  LPARAM lParam  		
							)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{//打开PE文件获取相关信息
			//Init_Parse_PE_Section(hwnd);
			//Init_Parse_PE_Import(hwnd);
			pPE_P->ParRelocTree(hwnd);
			break;
		}
	case WM_NOTIFY:
	{
		
		break;
	}
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
			break;
		}
	}

	return FALSE;

}

BOOL CALLBACK PEImportDlgProc(  									
							IN  HWND hwnd,  		
							IN  UINT uMsg,  		
							IN  WPARAM wParam,  		
							IN  LPARAM lParam  		
							)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{//打开PE文件获取相关信息
			//Init_Parse_PE_Section(hwnd);
			Init_Parse_PE_Import(hwnd);
			break;
		}
	case WM_NOTIFY:
	{
		NMHDR* pNMHDR=(NMHDR*)lParam;
		if(wParam==IDC_LIST_DLLINFO && pNMHDR->code==NM_CLICK)
		{
			pPE_P->ParImportClick(hwnd);
		}
		break;
	}
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
			break;
		}
	}

	return FALSE;


}

BOOL CALLBACK PESectionDlgProc(  									
							IN  HWND hwnd,  		
							IN  UINT uMsg,  		
							IN  WPARAM wParam,  		
							IN  LPARAM lParam  		
							)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{//打开PE文件获取相关信息
			//Init_Parse_PE_Section(hwnd);
			Init_Parse_PE_SECTION(hwnd);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
			break;
		}
	}

	return FALSE;

}

//目录信息窗口的消息处理函数
BOOL CALLBACK PEDirctoryDlgProc(  									
							IN  HWND hwnd,  		
							IN  UINT uMsg,  		
							IN  WPARAM wParam,  		
							IN  LPARAM lParam  		
							)
{
	switch(uMsg)
	{
	case WM_COMMAND:
		{
		switch(LOWORD(wParam))
			{
			case IDC_BUTTON_LOGOUT:
				{
					EndDialog(hwnd,0);
					return true;
				
				}
			case IDC_BUTTON_IMPORT:
			{
				DialogBox(hInstanceMain,MAKEINTRESOURCE(IDD_DIALOG_IMPORT),hwnd,PEImportDlgProc);
				return true;
			
			}
			case IDC_BUTTON_RELOC:
			{
				DialogBox(hInstanceMain,MAKEINTRESOURCE(IDD_DIALOG_RESOURCE),hwnd,PERelocDlgProc);
				return true;
			
			}

			}
			break;
		}
	case WM_INITDIALOG:
		{//打开PE文件获取相关信息
			Init_Parse_PE_Directory(hwnd);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
			break;
		}
	}

	return FALSE;
	
}  	
VOID Init_Parse_PE(HWND hwnd)
{
	pPE_P=new PE_Parse(PEFilePATH);//如何释放这个地方创建的内存？
	//OutputDebugStringF("%d\n",pPE_P->pPEHeader->NumberOfSections);
	TCHAR pStrEntry[10];
	TCHAR pStrImageBase[10];
	sprintf(pStrEntry,"%08X",pPE_P->pOptionalHeader->AddressOfEntryPoint);
	sprintf(pStrImageBase,"%08X",pPE_P->pOptionalHeader->ImageBase);
	SetWindowText(GetDlgItem(hwnd,IDC_EDIT_INTRY),pStrEntry);
	SetWindowText(GetDlgItem(hwnd,IDC_EDIT_IMAGEBASE),pStrImageBase);
	//pPE_P->~PE_Parse();     这个地方不是让你显式调用的，new出来的也是在堆上面    需要再复习一下虚函数表
	//delete pPE_P;
}
VOID updateModule(DWORD processID)
{

	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	memset(szProcessName,0,sizeof(MAX_PATH));
	DWORD cbNeeded=0;
	HMODULE hMods[1024];

	HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_READ,
                                   FALSE, processID );

    // Get the process information.
    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
			LV_ITEM vitem;
			//初始化
			memset(&vitem,0,sizeof(LV_ITEM));
			vitem.mask=LVIF_TEXT;
            TCHAR szModName[MAX_PATH];
			MODULEINFO ModuleInfo;

			TCHAR pStrImagBase[10];
			memset(pStrImagBase,0,10);

			TCHAR pStrDLLSize[10];
			memset(pStrDLLSize,0,10);
            // Get the full path to the module's file.

            if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.
				GetModuleInformation(hProcess, hMods[i], &ModuleInfo,sizeof(ModuleInfo));
                //OutputDebugStringF( TEXT("%s (0x%08X)   %08x   %08x\n"), szModName, hMods[i] ,ModuleInfo.lpBaseOfDll,ModuleInfo.SizeOfImage);
				sprintf(pStrImagBase,"%08X",ModuleInfo.lpBaseOfDll);
				sprintf(pStrDLLSize,"%08X",ModuleInfo.SizeOfImage);

				vitem.pszText=szModName;
				vitem.iItem=0;          //第几行
				vitem.iSubItem=0;           //第几列
				SendMessage(hListModuleInfo,LVM_INSERTITEM,0,(DWORD)&vitem);  //只有第一列是insertitem,后面的都是setitem

				vitem.pszText=pStrImagBase;
				vitem.iItem=0;          //第几行
				vitem.iSubItem=1;           //第几列
				SendMessage(hListModuleInfo,LVM_SETITEM,1,(DWORD)&vitem);

				vitem.pszText=pStrDLLSize;
				vitem.iItem=0;          //第几行
				vitem.iSubItem=2;           //第几列
				SendMessage(hListModuleInfo,LVM_SETITEM,2,(DWORD)&vitem);
            }
        }
    }
	CloseHandle( hProcess );

}
VOID UpdateProcessList(DWORD processID,DWORD row)
{	
	
	LV_ITEM vitem;
	//初始化
	memset(&vitem,0,sizeof(LV_ITEM));
	vitem.mask=LVIF_TEXT;
	TCHAR pStrID[10];
	memset(pStrID,0,10);
	TCHAR pStrDLLBase[10];
	memset(pStrDLLBase,0,10);
	TCHAR pStrImagSize[10];
	memset(pStrImagSize,0,10);
	sprintf(pStrID,"%08x",processID);
	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	MODULEINFO ModuleInfo;
	DWORD cbNeeded=0;
    // Get a handle to the process.

    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_READ,
                                   FALSE, processID );

    // Get the process information.

    if (NULL != hProcess )
    {

        HMODULE hMod;
        

        if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod), &cbNeeded) )
        {
            GetModuleBaseName( hProcess, hMod, szProcessName, sizeof(szProcessName)/sizeof(TCHAR) );
			GetModuleInformation(hProcess, hMod, &ModuleInfo,sizeof(ModuleInfo));
        }
    }
	sprintf(pStrDLLBase,"%08x",ModuleInfo.lpBaseOfDll);
	sprintf(pStrImagSize,"%08x",ModuleInfo.SizeOfImage);
	// update the processlist name and identifier.
	vitem.pszText=szProcessName;
	vitem.iItem=0;          //第几行
	vitem.iSubItem=0;           //第几列
	SendMessage(hListProcessInfo,LVM_INSERTITEM,0,(DWORD)&vitem);  //只有第一列是insertitem,后面的都是setitem

	vitem.pszText=pStrID;
	vitem.iItem=0;          //第几行
	vitem.iSubItem=1;           //第几列
	SendMessage(hListProcessInfo,LVM_SETITEM,1,(DWORD)&vitem);

	vitem.pszText=pStrDLLBase;
	vitem.iItem=0;          //第几行
	vitem.iSubItem=2;           //第几列
	SendMessage(hListProcessInfo,LVM_SETITEM,2,(DWORD)&vitem);

	vitem.pszText=pStrImagSize;
	vitem.iItem=0;          //第几行
	vitem.iSubItem=3;           //第几列
	SendMessage(hListProcessInfo,LVM_SETITEM,3,(DWORD)&vitem);
	CloseHandle( hProcess );

}		
//WIN32 就是消息驱动
VOID EnumModules(HWND hListProcess,WPARAM wParam,LPARAM lParam)
{
	DWORD dwRowId;
	TCHAR szPid[0x20];
	LV_ITEM lv;

	memset(&lv,0,sizeof(LV_ITEM));
	memset(szPid,0,0x20);
	DWORD processID;
	//获取选中行            dwRowId为行号
	dwRowId=SendMessage(hListProcess,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
	if(dwRowId==-1)
	{
		MessageBox(NULL,"出错了啊！","....",MB_OK);
		return;
	}
	//获取第几列
	lv.iSubItem=1;         //要获取的列
	lv.pszText=szPid;      //指定存储查询结果的缓冲区
	lv.cchTextMax=0x20;    //指定缓冲区大小
	SendMessage(hListProcess,LVM_GETITEMTEXT,dwRowId,(DWORD)&lv);
	sscanf(szPid,"%x",&processID);
	//根据pid的值调用API函数,并更新modulelist
	//UpdateModuleList(processID);
	//OutputDebugStringF( "\nProcess ID: %s %d\n", szPid,processID);
	updateModule(processID);
	
}

VOID enumProcess()
{
	//调用API
	
	DWORD aProcesses[1024], cbNeeded, cProcesses;
    DWORD i;

    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
    {
		MessageBox(NULL,"进程初始化错误","EXIT",MB_OK);
        return;
    }


    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.

    for ( i = 0; i < cProcesses; i++ )
    {
        if( aProcesses[i] != 0 )
        {
            UpdateProcessList(aProcesses[i],i);
			//PrintModules(aProcesses[i]);
        }
    }

}


VOID InitProcessListView(HWND hDlg)
{
	LV_COLUMN lv;
	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hListProcessInfo=GetDlgItem(hDlg,IDC_LIST_PROCESS);
	//设置整行选中
	SendMessage(hListProcessInfo,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	//第一列
	lv.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
	lv.pszText=TEXT("进程");
	lv.cx=150;              //列宽
	lv.iSubItem=0;
	SendMessage(hListProcessInfo,LVM_INSERTCOLUMN,0,(DWORD)&lv);

	//第二列
	lv.pszText=TEXT("PID");
	lv.cx=100;              //列宽
	lv.iSubItem=1;
	SendMessage(hListProcessInfo,LVM_INSERTCOLUMN,1,(DWORD)&lv);

		//第3列
	lv.pszText=TEXT("镜像基址");
	lv.cx=110;              //列宽
	lv.iSubItem=2;
	SendMessage(hListProcessInfo,LVM_INSERTCOLUMN,2,(DWORD)&lv);
		//第4列
	lv.pszText=TEXT("镜像大小");
	lv.cx=120;              //列宽
	lv.iSubItem=3;
	SendMessage(hListProcessInfo,LVM_INSERTCOLUMN,3,(DWORD)&lv);
	
	enumProcess();

}
VOID InitModuleListView(HWND hDlg)
{
	LV_COLUMN lv;
	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hListModuleInfo=GetDlgItem(hDlg,IDC_LIST_MODULE);
	//设置整行选中
	SendMessage(hListModuleInfo,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,LVS_EX_FULLROWSELECT);
	//第一列
	lv.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
	lv.pszText=TEXT("模块名称");
	lv.cx=200;              //列宽
	lv.iSubItem=0;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,0,(DWORD)&lv);

	//第二列
	lv.pszText=TEXT("模块位置");
	lv.cx=150;              //列宽
	lv.iSubItem=1;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,1,(DWORD)&lv);

	//第3列
	lv.pszText=TEXT("模块大小");
	lv.cx=150;              //列宽
	lv.iSubItem=2;
	SendMessage(hListModuleInfo,LVM_INSERTCOLUMN,2,(DWORD)&lv);
	
	//enumModule(hListProcess);

}


BOOL CALLBACK PECheckDlgProc(  									
							IN  HWND hwnd,  		
							IN  UINT uMsg,  		
							IN  WPARAM wParam,  		
							IN  LPARAM lParam  		
							)  		
{  		

	switch(uMsg)
	{
	case WM_COMMAND:
		{
		switch(LOWORD(wParam))
			{
			case IDC_BUTTON_PE_EXIT:
				{
					EndDialog(hwnd,0);
					return true;
				
				}
			case IDC_BUTTON_DIRECTORY:
				{
					DialogBox(hInstanceMain,MAKEINTRESOURCE(IDD_DIALOG_DIRCTORY),hwnd,PEDirctoryDlgProc);
					return true;
				}
			case IDC_BUTTON_SECTION:
				{
					DialogBox(hInstanceMain,MAKEINTRESOURCE(IDD_DIALOG_SECTION),hwnd,PESectionDlgProc);
					return true;
				}
			}
			break;
		}
	case WM_INITDIALOG:
		{//打开PE文件获取相关信息
			Init_Parse_PE(hwnd);
			//HWND hhh=GetDlgItem(hwnd,IDC_EDIT_INTRY);          

			//SetWindowText(hhh,"1000");
			//MessageBox(NULL,"HHH","DDD",MB_OK);
			//TCHAR szBuffer[128];
			//sprintf(szBuffer,"%x\n","00411110");
		//	SendDlgItemMessage(hwnd,IDC_EDIT_INTRY,WM_SETTEXT,0,(DWORD)szBuffer);
			//Init_Parse_PE(hwnd);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
			break;
		}
	}

	return FALSE;
}

//线程函数，用于加壳
DWORD WINAPI ThreadProcShell(				
			     LPVOID lpParameter   // thread data		
			    )
{
	LPVOID pFileBuffer=NULL;
	LPVOID pProtectFileBuf=NULL;
	LPVOID pNewBuffer=NULL;
	DWORD dwProPESize=0;


	TCHAR* ProtectPath=(TCHAR*)lpParameter;
	dwProPESize = ReadFileToBuffer(ProtectPath,&pProtectFileBuf);
	if(!pProtectFileBuf){
		printf("读取需要保护的程序缓冲区失败\n");
		::MessageBox(0,"【加壳失败-1】",ProtectPath,MB_OK);
		return -1;
	}
	//加密（省略）
	/*
	TODO:加密
	*/
	//Shell程序中增加节，并将加密的exe放到该节中
	DWORD dwShellSize=ReadFileToBuffer(ShellPath,&pFileBuffer);
	if(!pFileBuffer){
		printf("文件->缓冲区失败\n");
		free(pProtectFileBuf);
		::MessageBox(0,"【加壳失败-2】",ProtectPath,MB_OK);
		return -2;
	}
	if(!AddSecion(pFileBuffer,&pNewBuffer,pProtectFileBuf,dwProPESize,dwShellSize))
	{
		printf("增加节失败！\n");
		free(pFileBuffer);
		free(pProtectFileBuf);
		::MessageBox(0,"【加壳失败-3】",ProtectPath,MB_OK);
		return -3;
	}
	//存盘
	MemeryToFile(pNewBuffer,dwShellSize+dwProPESize,FILEPATH_OUT);
	free(pFileBuffer);
	free(pProtectFileBuf);
	free(pNewBuffer);
	::MessageBox(0,"【加壳成功】",ProtectPath,MB_OK);
	return 0;

}
BOOL CALLBACK PEShellDlgProc(  									
							IN  HWND hwnd,  		
							IN  UINT uMsg,  		
							IN  WPARAM wParam,  		
							IN  LPARAM lParam  		
							)  		
{  		

	switch(uMsg)
	{
	case WM_COMMAND:
		{
		switch(LOWORD(wParam))
			{
			case IDC_BUTTON_SHELL:
				{
					//DialogBox(hInstanceMain,MAKEINTRESOURCE(IDD_DIALOG_SECTION),hwnd,PESectionDlgProc);
					//创建线程去加壳			
					HANDLE hThread = ::CreateThread(NULL, 0, ThreadProcShell, 				
						(LPVOID)PEProtectPATH, 0, NULL);	
					CloseHandle(hThread);
					return true;
				}
			}
			break;
		}
	case WM_INITDIALOG:
		{
			HWND hShell=GetDlgItem(hwnd,IDC_EDIT1);
			HWND hProtect=GetDlgItem(hwnd,IDC_EDIT2);
			SetWindowText(hShell,ShellPath);
			SetWindowText(hProtect,PEProtectPATH);
			break;
		}
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
			break;
		}
	}

	return FALSE;
}

BOOL CALLBACK MainDlgProc(  									
							IN  HWND hwnd,  		
							IN  UINT uMsg,  		
							IN  WPARAM wParam,  		
							IN  LPARAM lParam  		
							)  		
{  		
	BOOL bRet=FALSE;
	OPENFILENAME stOpenFile;
	OPENFILENAME stOpenFile_Protct;
	switch(uMsg)								
	{								
		//窗口消息	
	case WM_INITDIALOG:
			InitProcessListView(hwnd);
			InitModuleListView(hwnd);
			break;
	case WM_CLOSE:
		{
			EndDialog(hwnd,0);
			if(NULL!=pPE_P)//把pPE_P释放了
			{
				delete pPE_P;
				pPE_P=NULL;
			}
			break;
		}
	case WM_NOTIFY:
		{
			NMHDR* pNMHDR=(NMHDR*)lParam;
			if(wParam==IDC_LIST_PROCESS && pNMHDR->code==NM_CLICK)
			{
				EnumModules(GetDlgItem(hwnd,IDC_LIST_PROCESS),wParam,lParam);
			}
			break;
		}
	case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
			case IDC_BUTTON_ABOUT:
				{
				
					MessageBox(NULL,"别乱点Zzz","【警告】",MB_OK);
					return true;
				
				}
			case IDC_BUTTON_PE:
				{
					TCHAR szPeFileExt[100]="*.exe;*.dll;*.scr;*.drv;*.sys";
					memset(PEFilePATH,0,MAX_PATH);
					memset(&stOpenFile,0,sizeof(OPENFILENAME));
					stOpenFile.lStructSize=sizeof(OPENFILENAME);
					stOpenFile.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
					stOpenFile.hwndOwner=hwnd;
					stOpenFile.lpstrFilter=szPeFileExt;
					stOpenFile.lpstrFile=PEFilePATH;
					stOpenFile.nMaxFile=MAX_PATH;
					GetOpenFileName(&stOpenFile);
					//MessageBox(NULL,szFileName,"选中的文件为",MB_OK);
					DialogBox(hInstanceMain,MAKEINTRESOURCE(IDD_DIALOG_PECHECK),hwnd,PECheckDlgProc);
					return true;
			
				}
			case IDC_BUTTON_PE2:
			{
				TCHAR szPeFileExt[100]="*.exe;*.dll;*.scr;*.drv;*.sys";
				memset(PEFilePATH,0,MAX_PATH);
				memset(&stOpenFile_Protct,0,sizeof(OPENFILENAME));
				stOpenFile_Protct.lStructSize=sizeof(OPENFILENAME);
				stOpenFile_Protct.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
				stOpenFile_Protct.hwndOwner=hwnd;
				stOpenFile_Protct.lpstrFilter=szPeFileExt;
				stOpenFile_Protct.lpstrFile=PEProtectPATH;
				stOpenFile_Protct.nMaxFile=MAX_PATH;
				GetOpenFileName(&stOpenFile_Protct);
				//MessageBox(NULL,szFileName,"选中的文件为",MB_OK);
				DialogBox(hInstanceMain,MAKEINTRESOURCE(IDD_DIALOG_SHELL),hwnd,PEShellDlgProc);
				return true;
		
			}
			case IDC_BUTTON_EXIT:
				{
					EndDialog(hwnd,0);
					if(NULL!=pPE_P)//把pPE_P释放了
					{
						delete pPE_P;
						pPE_P=NULL;
					}
					return true;
				}
			}
			break;
		}
	}								
	return false;								
}  									


int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{

	hInstanceMain=hInstance;
	INITCOMMONCONTROLSEX icex;				
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);				
	icex.dwICC = ICC_WIN95_CLASSES;				
	InitCommonControlsEx(&icex);				

 	// TODO: Place code here.
	DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG_MAIN),NULL,MainDlgProc);
	return 0;
}



