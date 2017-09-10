#pragma once

#include <Windows.h>
#include <string>
#include <list>

using namespace std;

namespace PEParser {

	enum PEFileType {
		NOT_A_PE_FILE,
		EXE_FILE,
		DLL_FILE,
		SYS_FILE,
		NOT_SUPPORTED
	};

	enum BITNess {
		BITNESS_64,
		BITNESS_32,
		BITNESS_UNKNOWN
	};

	typedef void * PEHANDLE;
	extern list<PEHANDLE> g_PEHandleList;

	PEHANDLE OpenPEFile(wstring const & p_PEFilePath);
	void FreePEFile(PEHANDLE m_PEHandle);

	PEFileType getPEFileType(PEHANDLE p_PEHandle);
	BITNess getBITNess(PEHANDLE p_PEHandle);
	IMAGE_DOS_HEADER getDOSHeader(PEHANDLE p_PEHandle);
	IMAGE_FILE_HEADER getFileHeader(PEHANDLE p_PEHandle);
	IMAGE_OPTIONAL_HEADER64 getOptHeader64(PEHANDLE p_PEHandle);
	IMAGE_OPTIONAL_HEADER32 getOptHeader32(PEHANDLE p_PEHandle);

	class PEParserException {
		public:
			wstring m_error_data;
			PEParserException(wstring const & p_error_data) {
				m_error_data = p_error_data;
			}
	};
}