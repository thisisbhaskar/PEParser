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

	PEHANDLE OpenFile(wstring const & p_pe_filepath);
	void CloseFile(PEHANDLE m_PEHandle);

	PEFileType getFileType(PEHANDLE p_pe_handle);
	BITNess getBITNess(PEHANDLE p_pe_handle);
	IMAGE_DOS_HEADER getDOSHeader(PEHANDLE p_pe_handle);
	IMAGE_FILE_HEADER getFileHeader(PEHANDLE p_pe_handle);
	IMAGE_OPTIONAL_HEADER64 getOptHeader64(PEHANDLE p_pe_handle);
	IMAGE_OPTIONAL_HEADER32 getOptHeader32(PEHANDLE p_pe_handle);
	size_t getNoOfSectionHeaders(PEHANDLE p_pe_handle);
    IMAGE_SECTION_HEADER* getSectionHeaders(PEHANDLE p_pe_handle, size_t & p_no_of_sections);

	class PEParserException {
		public:
			wstring m_error_data;
			PEParserException(wstring const & p_error_data) {
				m_error_data = p_error_data;
			}
	};
}