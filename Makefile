TARGET=EffModeWatcher.exe
SRC=main.cpp

!IFNDEF CONFIG
CONFIG=release
!ENDIF

!IF "$(CONFIG)" == "debug"
CFLAGS=/nologo /EHsc /std:c++17 /W4 /Od /Zi /DDEBUG /DUNICODE /D_UNICODE
!ELSE
CFLAGS=/nologo /EHsc /std:c++17 /W4 /O2 /DUNICODE /D_UNICODE
!ENDIF

all: $(TARGET)

$(TARGET): $(SRC)
	cl $(CFLAGS) $(SRC) /link /OUT:$(TARGET)

clean:
	-del /Q *.obj *.pdb *.ilk *.exe 2>nul
