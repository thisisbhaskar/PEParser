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

			PEInfo(HANDLE const & p_fileHandle);
			~PEInfo();

			void readHeaderData();
			enum CachedData {
				PE_HEADER_INFO
			};

			PEHeaderInfo * m_PEHeaderInfo;

		private:

			void getDOSHeader();
			void getNTHeader();
			void getSectionHeaders();

			HANDLE const m_PEFileHandle;
			set<CachedData> m_cachedData;
	};

	class PEHeaderInfo {

		public:

			PEHeaderInfo();
			~PEHeaderInfo();

			bool hasDOSHeader() {
				return m_hasDosHeader;
			}

			void hasDOSHeader(bool p_hasDOSHeader) {
				m_hasDosHeader = p_hasDOSHeader;
			}

			bool hasNTHeader() {
				return m_hasNTHeader;
			}

			void hasNTHeader(bool p_hasNTHeader) {
				m_hasNTHeader = p_hasNTHeader;
			}

			PEFileType getFileType() {
				return m_PEFileType;
			}

			BITNess getBITNess() {
				return m_BITNess;
			}

			IMAGE_DOS_HEADER getDOSHeader() {
				return m_dosHeader;
			}

			IMAGE_FILE_HEADER getFileHeader() {
				return m_fileHeader;
			}

			IMAGE_OPTIONAL_HEADER64 getOptHeader64() {
				return m_optionalHeader64;
			}

			IMAGE_OPTIONAL_HEADER32 getOptHeader32() {
				return m_optionalHeader32;
			}

			void setPEFileType(PEFileType const & p_PEFileType) {
				m_PEFileType = p_PEFileType;
			}

			void setBITNess(BITNess const & p_PEBITNess) {
				m_BITNess = p_PEBITNess;
			}

			void setDOSHeader(IMAGE_DOS_HEADER const & p_image_dos_header) {
				m_dosHeader = p_image_dos_header;
			}

			void setFileHeader(IMAGE_FILE_HEADER const & p_image_file_header) {
				m_fileHeader = p_image_file_header;
			}

			void setOptHeader64(IMAGE_OPTIONAL_HEADER64 const & p_image_opt_header64) {
				m_optionalHeader64 = p_image_opt_header64;
			}

			void setOptHeader32(IMAGE_OPTIONAL_HEADER32 const & p_image_opt_header32) {
				m_optionalHeader32 = p_image_opt_header32;
			}

			size_t getNoOfSections() {
				return m_noOfSections;
			}

			void reset();

			bool m_hasDosHeader;
			bool m_hasNTHeader;
			PEFileType m_PEFileType;
			BITNess m_BITNess;
			IMAGE_DOS_HEADER m_dosHeader;
			IMAGE_FILE_HEADER m_fileHeader;
			IMAGE_OPTIONAL_HEADER64 m_optionalHeader64;
			IMAGE_OPTIONAL_HEADER32 m_optionalHeader32;
			size_t m_noOfSections;
			IMAGE_SECTION_HEADER * m_sectionHeaderStart;
	};
}