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

    inline bool IsSupportedPEType(PEFileType p_type)
    {
        return (PEFileType::NOT_SUPPORTED != p_type &&
                PEFileType::NOT_A_PE_FILE != p_type);
    }

	enum BITNess {
		BITNESS_64,
		BITNESS_32,
		BITNESS_UNKNOWN
	};

	typedef void * PEHANDLE;
	extern list<PEHANDLE> g_PEHandleList;

	PEHANDLE OpenFile(wstring const & p_PEFilePath);
	void CloseFile(PEHANDLE m_PEHandle);

	PEFileType getFileType(PEHANDLE p_PEHandle);
	BITNess getBITNess(PEHANDLE p_PEHandle);
	IMAGE_DOS_HEADER getDOSHeader(PEHANDLE p_PEHandle);
	IMAGE_FILE_HEADER getFileHeader(PEHANDLE p_PEHandle);
	IMAGE_OPTIONAL_HEADER64 getOptHeader64(PEHANDLE p_PEHandle);
	IMAGE_OPTIONAL_HEADER32 getOptHeader32(PEHANDLE p_PEHandle);
	size_t getNoOfSectionHeaders(PEHANDLE p_PEHandle);
    IMAGE_SECTION_HEADER* getSectionHeaders(PEHANDLE p_PEHandle, size_t & p_no_of_sections);

	class PEParserException {
		public:
			wstring m_error_data;
			PEParserException(wstring const & p_error_data) {
				m_error_data = p_error_data;
			}
	};
}