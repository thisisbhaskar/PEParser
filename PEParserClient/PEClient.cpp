
#include <PEParser.h>

using namespace PEParser;

int main() {

	PEHANDLE l_peHandle = PEParser::OpenFile(L"C:\\Windows\\System32\\nvcoproc.bin");

	if (NULL != l_peHandle) {

        size_t l_section_count;
        IMAGE_SECTION_HEADER* l_buffer = PEParser::getSectionHeaders(l_peHandle, l_section_count);

		PEParser::getFileType(l_peHandle);

		PEParser::CloseFile(l_peHandle);
	}
	return 0;
}