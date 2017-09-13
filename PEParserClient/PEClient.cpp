
#include <PEParser.h>

using namespace PEParser;

int main() {

	PEHANDLE l_peHandle = PEParser::OpenFile(L"C:\\Windows\\System32\\nvcoproc.bin");

	if (NULL != l_peHandle) {
		char l_buffer[100];
		PEParser::getSectionHeaders(l_peHandle, (IMAGE_SECTION_HEADER*)l_buffer, sizeof(l_buffer));
		PEParser::getFileType(l_peHandle);
		PEParser::CloseFile(l_peHandle);
	}
	return 0;
}