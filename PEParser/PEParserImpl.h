#pragma once

#include "PEParser.h"
#include <Windows.h>

#include <string>
#include <list>
#include <set>

using namespace std;

namespace PEParser {

	class PEHeaderInfo;

	class PEInfo {

		public:

			PEInfo(HANDLE const & p_fileHandle,
                   HANDLE const & p_filemapping_handle,
                   PVOID const p_view_ponter);
			~PEInfo();

			void readHeaderData();
			enum CachedData {
				PE_HEADER_INFO
			};

			PEHeaderInfo * m_pe_headers_info;

		private:

			void getDOSHeader();
			void getNTHeader();
			void getSectionHeaders();

			HANDLE const m_PEFileHandle;
            HANDLE const m_filemapping_handle;
            PVOID const m_view_pointer;
			set<CachedData> m_cached_data;
	};

	class PEHeaderInfo {

		public:

			PEHeaderInfo();
			~PEHeaderInfo();

			bool hasDOSHeader() {
				return m_has_dos_header;
			}

			void hasDOSHeader(bool p_hasDOSHeader) {
				m_has_dos_header = p_hasDOSHeader;
			}

			bool hasNTHeader() {
				return m_has_nt_header;
			}

			void hasNTHeader(bool p_hasNTHeader) {
				m_has_nt_header = p_hasNTHeader;
			}

			PEFileType getFileType() {
				return m_pe_type;
			}

			BITNess getBITNess() {
				return m_bitness;
			}

			IMAGE_DOS_HEADER getDOSHeader() {
				return m_dos_header;
			}

			IMAGE_FILE_HEADER getFileHeader() {
				return m_file_header;
			}

			IMAGE_OPTIONAL_HEADER64 getOptHeader64() {
				return m_opt_header64;
			}

			IMAGE_OPTIONAL_HEADER32 getOptHeader32() {
				return m_opt_header32;
			}

			void setPEFileType(PEFileType const & p_PEFileType) {
				m_pe_type = p_PEFileType;
			}

			void setBITNess(BITNess const & p_PEBITNess) {
				m_bitness = p_PEBITNess;
			}

			void setDOSHeader(IMAGE_DOS_HEADER const & p_image_dos_header) {
				m_dos_header = p_image_dos_header;
			}

			void setFileHeader(IMAGE_FILE_HEADER const & p_image_file_header) {
				m_file_header = p_image_file_header;
			}

			void setOptHeader64(IMAGE_OPTIONAL_HEADER64 const & p_image_opt_header64) {
				m_opt_header64 = p_image_opt_header64;
			}

			void setOptHeader32(IMAGE_OPTIONAL_HEADER32 const & p_image_opt_header32) {
				m_opt_header32 = p_image_opt_header32;
			}

			size_t getNoOfSections() {
				return m_no_sections;
			}

			void reset();

			bool m_has_dos_header;
			bool m_has_nt_header;
			PEFileType m_pe_type;
			BITNess m_bitness;
			IMAGE_DOS_HEADER m_dos_header;
			IMAGE_FILE_HEADER m_file_header;
			IMAGE_OPTIONAL_HEADER64 m_opt_header64;
			IMAGE_OPTIONAL_HEADER32 m_opt_header32;
			size_t m_no_sections;
			IMAGE_SECTION_HEADER * m_sect_header_start;
	};
}