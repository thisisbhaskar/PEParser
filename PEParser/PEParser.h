#pragma once

#include <Windows.h>
#include <string>
#include <list>

using namespace std;

namespace PEParser {

	typedef void * PEHANDLE;
	
	list<PEHANDLE> g_PEHandleList;

	PEHANDLE OpenPEFile();
	void FreePEHandle(PEHANDLE m_PEHandle);

	enum PEFileType {
		NOT_A_PE_FILE,
		EXE_FILE,
		DLL_FILE,
		SYS_FILE,
		NO_SUPPORT
	};

	enum BITNess {
		BITNESS_64,
		BITNESS_32
	};


	class PEHeaderInfo {

		public:
			PEHeaderInfo();
			~PEHeaderInfo();

			wstring getFilePath();
			PEFileType getPEFileType();
			BITNess getBITNess();
			IMAGE_DOS_HEADER getDOSHeader();
			IMAGE_FILE_HEADER getFileHeader();
			IMAGE_OPTIONAL_HEADER64 getOptHeader64();
			IMAGE_OPTIONAL_HEADER32 getOptHeader32();

		private:

			wstring filePath;

			PEFileType m_PEFileType;
			BITNess m_BITNess;

			PIMAGE_DOS_HEADER m_dosHeader;
			PIMAGE_FILE_HEADER m_fileHeader;
			PIMAGE_OPTIONAL_HEADER64 m_optionalHeader64;
			PIMAGE_OPTIONAL_HEADER32 m_optionalHeader32;
	};
}