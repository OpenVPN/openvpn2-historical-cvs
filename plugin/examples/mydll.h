#ifdef __MINGW32_VERSION

#ifdef __cplusplus
     #define cppfudge "C"
#else
     #define cppfudge
#endif

#ifdef BUILD_DLL
     // the dll exports
     #define EXPORT __declspec(dllexport)
#else
     // the exe imports
     #define EXPORT extern cppfudge  __declspec(dllimport)
#endif

#else

#define EXPORT

#endif
