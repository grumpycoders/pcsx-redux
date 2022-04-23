/*
 * This file was generated with gl3w_gen.py, part of gl3w
 * (hosted at https://github.com/skaslev/gl3w)
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef __gl3w_h_
#define __gl3w_h_
#include <GL/glcorearb.h>
#ifndef GL3W_API
#define GL3W_API
#endif
#ifndef __gl_h_
#define __gl_h_
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define GL3W_OK 0
#define GL3W_ERROR_INIT -1
#define GL3W_ERROR_LIBRARY_OPEN -2
#define GL3W_ERROR_OPENGL_VERSION -3
typedef void (*GL3WglProc)(void);
typedef GL3WglProc (*GL3WGetProcAddressProc)(const char *proc);
/* gl3w api */
GL3W_API int gl3wInit(void);
GL3W_API int gl3wInit2(GL3WGetProcAddressProc proc);
GL3W_API int gl3wIsSupported(int major, int minor);
GL3W_API GL3WglProc gl3wGetProcAddress(const char *proc);
/* gl3w internal state */
union GL3WProcs {
	GL3WglProc ptr[565];
	struct {
		PFNGLACTIVESHADERPROGRAMPROC                            ActiveShaderProgram;
		PFNGLACTIVETEXTUREPROC                                  ActiveTexture;
		PFNGLATTACHSHADERPROC                                   AttachShader;
		PFNGLBEGINCONDITIONALRENDERPROC                         BeginConditionalRender;
		PFNGLBEGINQUERYPROC                                     BeginQuery;
		PFNGLBEGINQUERYINDEXEDPROC                              BeginQueryIndexed;
		PFNGLBEGINTRANSFORMFEEDBACKPROC                         BeginTransformFeedback;
		PFNGLBINDATTRIBLOCATIONPROC                             BindAttribLocation;
		PFNGLBINDBUFFERPROC                                     BindBuffer;
		PFNGLBINDBUFFERBASEPROC                                 BindBufferBase;
		PFNGLBINDBUFFERRANGEPROC                                BindBufferRange;
		PFNGLBINDFRAGDATALOCATIONPROC                           BindFragDataLocation;
		PFNGLBINDFRAGDATALOCATIONINDEXEDPROC                    BindFragDataLocationIndexed;
		PFNGLBINDFRAMEBUFFERPROC                                BindFramebuffer;
		PFNGLBINDIMAGETEXTUREPROC                               BindImageTexture;
		PFNGLBINDPROGRAMPIPELINEPROC                            BindProgramPipeline;
		PFNGLBINDRENDERBUFFERPROC                               BindRenderbuffer;
		PFNGLBINDSAMPLERPROC                                    BindSampler;
		PFNGLBINDTEXTUREPROC                                    BindTexture;
		PFNGLBINDTRANSFORMFEEDBACKPROC                          BindTransformFeedback;
		PFNGLBINDVERTEXARRAYPROC                                BindVertexArray;
		PFNGLBINDVERTEXBUFFERPROC                               BindVertexBuffer;
		PFNGLBLENDCOLORPROC                                     BlendColor;
		PFNGLBLENDEQUATIONPROC                                  BlendEquation;
		PFNGLBLENDEQUATIONSEPARATEPROC                          BlendEquationSeparate;
		PFNGLBLENDEQUATIONSEPARATEIPROC                         BlendEquationSeparatei;
		PFNGLBLENDEQUATIONIPROC                                 BlendEquationi;
		PFNGLBLENDFUNCPROC                                      BlendFunc;
		PFNGLBLENDFUNCSEPARATEPROC                              BlendFuncSeparate;
		PFNGLBLENDFUNCSEPARATEIPROC                             BlendFuncSeparatei;
		PFNGLBLENDFUNCIPROC                                     BlendFunci;
		PFNGLBLITFRAMEBUFFERPROC                                BlitFramebuffer;
		PFNGLBUFFERDATAPROC                                     BufferData;
		PFNGLBUFFERSTORAGEPROC                                  BufferStorage;
		PFNGLBUFFERSUBDATAPROC                                  BufferSubData;
		PFNGLCHECKFRAMEBUFFERSTATUSPROC                         CheckFramebufferStatus;
		PFNGLCLAMPCOLORPROC                                     ClampColor;
		PFNGLCLEARPROC                                          Clear;
		PFNGLCLEARBUFFERDATAPROC                                ClearBufferData;
		PFNGLCLEARBUFFERSUBDATAPROC                             ClearBufferSubData;
		PFNGLCLEARBUFFERFIPROC                                  ClearBufferfi;
		PFNGLCLEARBUFFERFVPROC                                  ClearBufferfv;
		PFNGLCLEARBUFFERIVPROC                                  ClearBufferiv;
		PFNGLCLEARBUFFERUIVPROC                                 ClearBufferuiv;
		PFNGLCLEARCOLORPROC                                     ClearColor;
		PFNGLCLEARDEPTHPROC                                     ClearDepth;
		PFNGLCLEARDEPTHFPROC                                    ClearDepthf;
		PFNGLCLEARSTENCILPROC                                   ClearStencil;
		PFNGLCLIENTWAITSYNCPROC                                 ClientWaitSync;
		PFNGLCOLORMASKPROC                                      ColorMask;
		PFNGLCOLORMASKIPROC                                     ColorMaski;
		PFNGLCOLORP3UIPROC                                      ColorP3ui;
		PFNGLCOLORP3UIVPROC                                     ColorP3uiv;
		PFNGLCOLORP4UIPROC                                      ColorP4ui;
		PFNGLCOLORP4UIVPROC                                     ColorP4uiv;
		PFNGLCOMPILESHADERPROC                                  CompileShader;
		PFNGLCOMPRESSEDTEXIMAGE1DPROC                           CompressedTexImage1D;
		PFNGLCOMPRESSEDTEXIMAGE2DPROC                           CompressedTexImage2D;
		PFNGLCOMPRESSEDTEXIMAGE3DPROC                           CompressedTexImage3D;
		PFNGLCOMPRESSEDTEXSUBIMAGE1DPROC                        CompressedTexSubImage1D;
		PFNGLCOMPRESSEDTEXSUBIMAGE2DPROC                        CompressedTexSubImage2D;
		PFNGLCOMPRESSEDTEXSUBIMAGE3DPROC                        CompressedTexSubImage3D;
		PFNGLCOPYBUFFERSUBDATAPROC                              CopyBufferSubData;
		PFNGLCOPYIMAGESUBDATAPROC                               CopyImageSubData;
		PFNGLCOPYTEXIMAGE1DPROC                                 CopyTexImage1D;
		PFNGLCOPYTEXIMAGE2DPROC                                 CopyTexImage2D;
		PFNGLCOPYTEXSUBIMAGE1DPROC                              CopyTexSubImage1D;
		PFNGLCOPYTEXSUBIMAGE2DPROC                              CopyTexSubImage2D;
		PFNGLCOPYTEXSUBIMAGE3DPROC                              CopyTexSubImage3D;
		PFNGLCREATEPROGRAMPROC                                  CreateProgram;
		PFNGLCREATESHADERPROC                                   CreateShader;
		PFNGLCREATESHADERPROGRAMVPROC                           CreateShaderProgramv;
		PFNGLCULLFACEPROC                                       CullFace;
		PFNGLDEBUGMESSAGECALLBACKPROC                           DebugMessageCallback;
		PFNGLDEBUGMESSAGECONTROLPROC                            DebugMessageControl;
		PFNGLDEBUGMESSAGEINSERTPROC                             DebugMessageInsert;
		PFNGLDELETEBUFFERSPROC                                  DeleteBuffers;
		PFNGLDELETEFRAMEBUFFERSPROC                             DeleteFramebuffers;
		PFNGLDELETEPROGRAMPROC                                  DeleteProgram;
		PFNGLDELETEPROGRAMPIPELINESPROC                         DeleteProgramPipelines;
		PFNGLDELETEQUERIESPROC                                  DeleteQueries;
		PFNGLDELETERENDERBUFFERSPROC                            DeleteRenderbuffers;
		PFNGLDELETESAMPLERSPROC                                 DeleteSamplers;
		PFNGLDELETESHADERPROC                                   DeleteShader;
		PFNGLDELETESYNCPROC                                     DeleteSync;
		PFNGLDELETETEXTURESPROC                                 DeleteTextures;
		PFNGLDELETETRANSFORMFEEDBACKSPROC                       DeleteTransformFeedbacks;
		PFNGLDELETEVERTEXARRAYSPROC                             DeleteVertexArrays;
		PFNGLDEPTHFUNCPROC                                      DepthFunc;
		PFNGLDEPTHMASKPROC                                      DepthMask;
		PFNGLDEPTHRANGEPROC                                     DepthRange;
		PFNGLDEPTHRANGEARRAYVPROC                               DepthRangeArrayv;
		PFNGLDEPTHRANGEINDEXEDPROC                              DepthRangeIndexed;
		PFNGLDEPTHRANGEFPROC                                    DepthRangef;
		PFNGLDETACHSHADERPROC                                   DetachShader;
		PFNGLDISABLEPROC                                        Disable;
		PFNGLDISABLEVERTEXATTRIBARRAYPROC                       DisableVertexAttribArray;
		PFNGLDISABLEIPROC                                       Disablei;
		PFNGLDISPATCHCOMPUTEPROC                                DispatchCompute;
		PFNGLDISPATCHCOMPUTEINDIRECTPROC                        DispatchComputeIndirect;
		PFNGLDRAWARRAYSPROC                                     DrawArrays;
		PFNGLDRAWARRAYSINDIRECTPROC                             DrawArraysIndirect;
		PFNGLDRAWARRAYSINSTANCEDPROC                            DrawArraysInstanced;
		PFNGLDRAWARRAYSINSTANCEDBASEINSTANCEPROC                DrawArraysInstancedBaseInstance;
		PFNGLDRAWBUFFERPROC                                     DrawBuffer;
		PFNGLDRAWBUFFERSPROC                                    DrawBuffers;
		PFNGLDRAWELEMENTSPROC                                   DrawElements;
		PFNGLDRAWELEMENTSBASEVERTEXPROC                         DrawElementsBaseVertex;
		PFNGLDRAWELEMENTSINDIRECTPROC                           DrawElementsIndirect;
		PFNGLDRAWELEMENTSINSTANCEDPROC                          DrawElementsInstanced;
		PFNGLDRAWELEMENTSINSTANCEDBASEINSTANCEPROC              DrawElementsInstancedBaseInstance;
		PFNGLDRAWELEMENTSINSTANCEDBASEVERTEXPROC                DrawElementsInstancedBaseVertex;
		PFNGLDRAWELEMENTSINSTANCEDBASEVERTEXBASEINSTANCEPROC    DrawElementsInstancedBaseVertexBaseInstance;
		PFNGLDRAWRANGEELEMENTSPROC                              DrawRangeElements;
		PFNGLDRAWRANGEELEMENTSBASEVERTEXPROC                    DrawRangeElementsBaseVertex;
		PFNGLDRAWTRANSFORMFEEDBACKPROC                          DrawTransformFeedback;
		PFNGLDRAWTRANSFORMFEEDBACKINSTANCEDPROC                 DrawTransformFeedbackInstanced;
		PFNGLDRAWTRANSFORMFEEDBACKSTREAMPROC                    DrawTransformFeedbackStream;
		PFNGLDRAWTRANSFORMFEEDBACKSTREAMINSTANCEDPROC           DrawTransformFeedbackStreamInstanced;
		PFNGLENABLEPROC                                         Enable;
		PFNGLENABLEVERTEXATTRIBARRAYPROC                        EnableVertexAttribArray;
		PFNGLENABLEIPROC                                        Enablei;
		PFNGLENDCONDITIONALRENDERPROC                           EndConditionalRender;
		PFNGLENDQUERYPROC                                       EndQuery;
		PFNGLENDQUERYINDEXEDPROC                                EndQueryIndexed;
		PFNGLENDTRANSFORMFEEDBACKPROC                           EndTransformFeedback;
		PFNGLFENCESYNCPROC                                      FenceSync;
		PFNGLFINISHPROC                                         Finish;
		PFNGLFLUSHPROC                                          Flush;
		PFNGLFLUSHMAPPEDBUFFERRANGEPROC                         FlushMappedBufferRange;
		PFNGLFRAMEBUFFERPARAMETERIPROC                          FramebufferParameteri;
		PFNGLFRAMEBUFFERRENDERBUFFERPROC                        FramebufferRenderbuffer;
		PFNGLFRAMEBUFFERTEXTUREPROC                             FramebufferTexture;
		PFNGLFRAMEBUFFERTEXTURE1DPROC                           FramebufferTexture1D;
		PFNGLFRAMEBUFFERTEXTURE2DPROC                           FramebufferTexture2D;
		PFNGLFRAMEBUFFERTEXTURE3DPROC                           FramebufferTexture3D;
		PFNGLFRAMEBUFFERTEXTURELAYERPROC                        FramebufferTextureLayer;
		PFNGLFRONTFACEPROC                                      FrontFace;
		PFNGLGENBUFFERSPROC                                     GenBuffers;
		PFNGLGENFRAMEBUFFERSPROC                                GenFramebuffers;
		PFNGLGENPROGRAMPIPELINESPROC                            GenProgramPipelines;
		PFNGLGENQUERIESPROC                                     GenQueries;
		PFNGLGENRENDERBUFFERSPROC                               GenRenderbuffers;
		PFNGLGENSAMPLERSPROC                                    GenSamplers;
		PFNGLGENTEXTURESPROC                                    GenTextures;
		PFNGLGENTRANSFORMFEEDBACKSPROC                          GenTransformFeedbacks;
		PFNGLGENVERTEXARRAYSPROC                                GenVertexArrays;
		PFNGLGENERATEMIPMAPPROC                                 GenerateMipmap;
		PFNGLGETACTIVEATOMICCOUNTERBUFFERIVPROC                 GetActiveAtomicCounterBufferiv;
		PFNGLGETACTIVEATTRIBPROC                                GetActiveAttrib;
		PFNGLGETACTIVESUBROUTINENAMEPROC                        GetActiveSubroutineName;
		PFNGLGETACTIVESUBROUTINEUNIFORMNAMEPROC                 GetActiveSubroutineUniformName;
		PFNGLGETACTIVESUBROUTINEUNIFORMIVPROC                   GetActiveSubroutineUniformiv;
		PFNGLGETACTIVEUNIFORMPROC                               GetActiveUniform;
		PFNGLGETACTIVEUNIFORMBLOCKNAMEPROC                      GetActiveUniformBlockName;
		PFNGLGETACTIVEUNIFORMBLOCKIVPROC                        GetActiveUniformBlockiv;
		PFNGLGETACTIVEUNIFORMNAMEPROC                           GetActiveUniformName;
		PFNGLGETACTIVEUNIFORMSIVPROC                            GetActiveUniformsiv;
		PFNGLGETATTACHEDSHADERSPROC                             GetAttachedShaders;
		PFNGLGETATTRIBLOCATIONPROC                              GetAttribLocation;
		PFNGLGETBOOLEANI_VPROC                                  GetBooleani_v;
		PFNGLGETBOOLEANVPROC                                    GetBooleanv;
		PFNGLGETBUFFERPARAMETERI64VPROC                         GetBufferParameteri64v;
		PFNGLGETBUFFERPARAMETERIVPROC                           GetBufferParameteriv;
		PFNGLGETBUFFERPOINTERVPROC                              GetBufferPointerv;
		PFNGLGETBUFFERSUBDATAPROC                               GetBufferSubData;
		PFNGLGETCOMPRESSEDTEXIMAGEPROC                          GetCompressedTexImage;
		PFNGLGETDEBUGMESSAGELOGPROC                             GetDebugMessageLog;
		PFNGLGETDOUBLEI_VPROC                                   GetDoublei_v;
		PFNGLGETDOUBLEVPROC                                     GetDoublev;
		PFNGLGETERRORPROC                                       GetError;
		PFNGLGETFLOATI_VPROC                                    GetFloati_v;
		PFNGLGETFLOATVPROC                                      GetFloatv;
		PFNGLGETFRAGDATAINDEXPROC                               GetFragDataIndex;
		PFNGLGETFRAGDATALOCATIONPROC                            GetFragDataLocation;
		PFNGLGETFRAMEBUFFERATTACHMENTPARAMETERIVPROC            GetFramebufferAttachmentParameteriv;
		PFNGLGETFRAMEBUFFERPARAMETERIVPROC                      GetFramebufferParameteriv;
		PFNGLGETINTEGER64I_VPROC                                GetInteger64i_v;
		PFNGLGETINTEGER64VPROC                                  GetInteger64v;
		PFNGLGETINTEGERI_VPROC                                  GetIntegeri_v;
		PFNGLGETINTEGERVPROC                                    GetIntegerv;
		PFNGLGETINTERNALFORMATI64VPROC                          GetInternalformati64v;
		PFNGLGETINTERNALFORMATIVPROC                            GetInternalformativ;
		PFNGLGETMULTISAMPLEFVPROC                               GetMultisamplefv;
		PFNGLGETOBJECTLABELPROC                                 GetObjectLabel;
		PFNGLGETOBJECTPTRLABELPROC                              GetObjectPtrLabel;
		PFNGLGETPOINTERVPROC                                    GetPointerv;
		PFNGLGETPROGRAMBINARYPROC                               GetProgramBinary;
		PFNGLGETPROGRAMINFOLOGPROC                              GetProgramInfoLog;
		PFNGLGETPROGRAMINTERFACEIVPROC                          GetProgramInterfaceiv;
		PFNGLGETPROGRAMPIPELINEINFOLOGPROC                      GetProgramPipelineInfoLog;
		PFNGLGETPROGRAMPIPELINEIVPROC                           GetProgramPipelineiv;
		PFNGLGETPROGRAMRESOURCEINDEXPROC                        GetProgramResourceIndex;
		PFNGLGETPROGRAMRESOURCELOCATIONPROC                     GetProgramResourceLocation;
		PFNGLGETPROGRAMRESOURCELOCATIONINDEXPROC                GetProgramResourceLocationIndex;
		PFNGLGETPROGRAMRESOURCENAMEPROC                         GetProgramResourceName;
		PFNGLGETPROGRAMRESOURCEIVPROC                           GetProgramResourceiv;
		PFNGLGETPROGRAMSTAGEIVPROC                              GetProgramStageiv;
		PFNGLGETPROGRAMIVPROC                                   GetProgramiv;
		PFNGLGETQUERYINDEXEDIVPROC                              GetQueryIndexediv;
		PFNGLGETQUERYOBJECTI64VPROC                             GetQueryObjecti64v;
		PFNGLGETQUERYOBJECTIVPROC                               GetQueryObjectiv;
		PFNGLGETQUERYOBJECTUI64VPROC                            GetQueryObjectui64v;
		PFNGLGETQUERYOBJECTUIVPROC                              GetQueryObjectuiv;
		PFNGLGETQUERYIVPROC                                     GetQueryiv;
		PFNGLGETRENDERBUFFERPARAMETERIVPROC                     GetRenderbufferParameteriv;
		PFNGLGETSAMPLERPARAMETERIIVPROC                         GetSamplerParameterIiv;
		PFNGLGETSAMPLERPARAMETERIUIVPROC                        GetSamplerParameterIuiv;
		PFNGLGETSAMPLERPARAMETERFVPROC                          GetSamplerParameterfv;
		PFNGLGETSAMPLERPARAMETERIVPROC                          GetSamplerParameteriv;
		PFNGLGETSHADERINFOLOGPROC                               GetShaderInfoLog;
		PFNGLGETSHADERPRECISIONFORMATPROC                       GetShaderPrecisionFormat;
		PFNGLGETSHADERSOURCEPROC                                GetShaderSource;
		PFNGLGETSHADERIVPROC                                    GetShaderiv;
		PFNGLGETSTRINGPROC                                      GetString;
		PFNGLGETSTRINGIPROC                                     GetStringi;
		PFNGLGETSUBROUTINEINDEXPROC                             GetSubroutineIndex;
		PFNGLGETSUBROUTINEUNIFORMLOCATIONPROC                   GetSubroutineUniformLocation;
		PFNGLGETSYNCIVPROC                                      GetSynciv;
		PFNGLGETTEXIMAGEPROC                                    GetTexImage;
		PFNGLGETTEXLEVELPARAMETERFVPROC                         GetTexLevelParameterfv;
		PFNGLGETTEXLEVELPARAMETERIVPROC                         GetTexLevelParameteriv;
		PFNGLGETTEXPARAMETERIIVPROC                             GetTexParameterIiv;
		PFNGLGETTEXPARAMETERIUIVPROC                            GetTexParameterIuiv;
		PFNGLGETTEXPARAMETERFVPROC                              GetTexParameterfv;
		PFNGLGETTEXPARAMETERIVPROC                              GetTexParameteriv;
		PFNGLGETTRANSFORMFEEDBACKVARYINGPROC                    GetTransformFeedbackVarying;
		PFNGLGETUNIFORMBLOCKINDEXPROC                           GetUniformBlockIndex;
		PFNGLGETUNIFORMINDICESPROC                              GetUniformIndices;
		PFNGLGETUNIFORMLOCATIONPROC                             GetUniformLocation;
		PFNGLGETUNIFORMSUBROUTINEUIVPROC                        GetUniformSubroutineuiv;
		PFNGLGETUNIFORMDVPROC                                   GetUniformdv;
		PFNGLGETUNIFORMFVPROC                                   GetUniformfv;
		PFNGLGETUNIFORMIVPROC                                   GetUniformiv;
		PFNGLGETUNIFORMUIVPROC                                  GetUniformuiv;
		PFNGLGETVERTEXATTRIBIIVPROC                             GetVertexAttribIiv;
		PFNGLGETVERTEXATTRIBIUIVPROC                            GetVertexAttribIuiv;
		PFNGLGETVERTEXATTRIBLDVPROC                             GetVertexAttribLdv;
		PFNGLGETVERTEXATTRIBPOINTERVPROC                        GetVertexAttribPointerv;
		PFNGLGETVERTEXATTRIBDVPROC                              GetVertexAttribdv;
		PFNGLGETVERTEXATTRIBFVPROC                              GetVertexAttribfv;
		PFNGLGETVERTEXATTRIBIVPROC                              GetVertexAttribiv;
		PFNGLHINTPROC                                           Hint;
		PFNGLINVALIDATEBUFFERDATAPROC                           InvalidateBufferData;
		PFNGLINVALIDATEBUFFERSUBDATAPROC                        InvalidateBufferSubData;
		PFNGLINVALIDATEFRAMEBUFFERPROC                          InvalidateFramebuffer;
		PFNGLINVALIDATESUBFRAMEBUFFERPROC                       InvalidateSubFramebuffer;
		PFNGLINVALIDATETEXIMAGEPROC                             InvalidateTexImage;
		PFNGLINVALIDATETEXSUBIMAGEPROC                          InvalidateTexSubImage;
		PFNGLISBUFFERPROC                                       IsBuffer;
		PFNGLISENABLEDPROC                                      IsEnabled;
		PFNGLISENABLEDIPROC                                     IsEnabledi;
		PFNGLISFRAMEBUFFERPROC                                  IsFramebuffer;
		PFNGLISPROGRAMPROC                                      IsProgram;
		PFNGLISPROGRAMPIPELINEPROC                              IsProgramPipeline;
		PFNGLISQUERYPROC                                        IsQuery;
		PFNGLISRENDERBUFFERPROC                                 IsRenderbuffer;
		PFNGLISSAMPLERPROC                                      IsSampler;
		PFNGLISSHADERPROC                                       IsShader;
		PFNGLISSYNCPROC                                         IsSync;
		PFNGLISTEXTUREPROC                                      IsTexture;
		PFNGLISTRANSFORMFEEDBACKPROC                            IsTransformFeedback;
		PFNGLISVERTEXARRAYPROC                                  IsVertexArray;
		PFNGLLINEWIDTHPROC                                      LineWidth;
		PFNGLLINKPROGRAMPROC                                    LinkProgram;
		PFNGLLOGICOPPROC                                        LogicOp;
		PFNGLMAPBUFFERPROC                                      MapBuffer;
		PFNGLMAPBUFFERRANGEPROC                                 MapBufferRange;
		PFNGLMEMORYBARRIERPROC                                  MemoryBarrier;
		PFNGLMINSAMPLESHADINGPROC                               MinSampleShading;
		PFNGLMULTIDRAWARRAYSPROC                                MultiDrawArrays;
		PFNGLMULTIDRAWARRAYSINDIRECTPROC                        MultiDrawArraysIndirect;
		PFNGLMULTIDRAWELEMENTSPROC                              MultiDrawElements;
		PFNGLMULTIDRAWELEMENTSBASEVERTEXPROC                    MultiDrawElementsBaseVertex;
		PFNGLMULTIDRAWELEMENTSINDIRECTPROC                      MultiDrawElementsIndirect;
		PFNGLMULTITEXCOORDP1UIPROC                              MultiTexCoordP1ui;
		PFNGLMULTITEXCOORDP1UIVPROC                             MultiTexCoordP1uiv;
		PFNGLMULTITEXCOORDP2UIPROC                              MultiTexCoordP2ui;
		PFNGLMULTITEXCOORDP2UIVPROC                             MultiTexCoordP2uiv;
		PFNGLMULTITEXCOORDP3UIPROC                              MultiTexCoordP3ui;
		PFNGLMULTITEXCOORDP3UIVPROC                             MultiTexCoordP3uiv;
		PFNGLMULTITEXCOORDP4UIPROC                              MultiTexCoordP4ui;
		PFNGLMULTITEXCOORDP4UIVPROC                             MultiTexCoordP4uiv;
		PFNGLNORMALP3UIPROC                                     NormalP3ui;
		PFNGLNORMALP3UIVPROC                                    NormalP3uiv;
		PFNGLOBJECTLABELPROC                                    ObjectLabel;
		PFNGLOBJECTPTRLABELPROC                                 ObjectPtrLabel;
		PFNGLPATCHPARAMETERFVPROC                               PatchParameterfv;
		PFNGLPATCHPARAMETERIPROC                                PatchParameteri;
		PFNGLPAUSETRANSFORMFEEDBACKPROC                         PauseTransformFeedback;
		PFNGLPIXELSTOREFPROC                                    PixelStoref;
		PFNGLPIXELSTOREIPROC                                    PixelStorei;
		PFNGLPOINTPARAMETERFPROC                                PointParameterf;
		PFNGLPOINTPARAMETERFVPROC                               PointParameterfv;
		PFNGLPOINTPARAMETERIPROC                                PointParameteri;
		PFNGLPOINTPARAMETERIVPROC                               PointParameteriv;
		PFNGLPOINTSIZEPROC                                      PointSize;
		PFNGLPOLYGONMODEPROC                                    PolygonMode;
		PFNGLPOLYGONOFFSETPROC                                  PolygonOffset;
		PFNGLPOPDEBUGGROUPPROC                                  PopDebugGroup;
		PFNGLPRIMITIVERESTARTINDEXPROC                          PrimitiveRestartIndex;
		PFNGLPROGRAMBINARYPROC                                  ProgramBinary;
		PFNGLPROGRAMPARAMETERIPROC                              ProgramParameteri;
		PFNGLPROGRAMUNIFORM1DPROC                               ProgramUniform1d;
		PFNGLPROGRAMUNIFORM1DVPROC                              ProgramUniform1dv;
		PFNGLPROGRAMUNIFORM1FPROC                               ProgramUniform1f;
		PFNGLPROGRAMUNIFORM1FVPROC                              ProgramUniform1fv;
		PFNGLPROGRAMUNIFORM1IPROC                               ProgramUniform1i;
		PFNGLPROGRAMUNIFORM1IVPROC                              ProgramUniform1iv;
		PFNGLPROGRAMUNIFORM1UIPROC                              ProgramUniform1ui;
		PFNGLPROGRAMUNIFORM1UIVPROC                             ProgramUniform1uiv;
		PFNGLPROGRAMUNIFORM2DPROC                               ProgramUniform2d;
		PFNGLPROGRAMUNIFORM2DVPROC                              ProgramUniform2dv;
		PFNGLPROGRAMUNIFORM2FPROC                               ProgramUniform2f;
		PFNGLPROGRAMUNIFORM2FVPROC                              ProgramUniform2fv;
		PFNGLPROGRAMUNIFORM2IPROC                               ProgramUniform2i;
		PFNGLPROGRAMUNIFORM2IVPROC                              ProgramUniform2iv;
		PFNGLPROGRAMUNIFORM2UIPROC                              ProgramUniform2ui;
		PFNGLPROGRAMUNIFORM2UIVPROC                             ProgramUniform2uiv;
		PFNGLPROGRAMUNIFORM3DPROC                               ProgramUniform3d;
		PFNGLPROGRAMUNIFORM3DVPROC                              ProgramUniform3dv;
		PFNGLPROGRAMUNIFORM3FPROC                               ProgramUniform3f;
		PFNGLPROGRAMUNIFORM3FVPROC                              ProgramUniform3fv;
		PFNGLPROGRAMUNIFORM3IPROC                               ProgramUniform3i;
		PFNGLPROGRAMUNIFORM3IVPROC                              ProgramUniform3iv;
		PFNGLPROGRAMUNIFORM3UIPROC                              ProgramUniform3ui;
		PFNGLPROGRAMUNIFORM3UIVPROC                             ProgramUniform3uiv;
		PFNGLPROGRAMUNIFORM4DPROC                               ProgramUniform4d;
		PFNGLPROGRAMUNIFORM4DVPROC                              ProgramUniform4dv;
		PFNGLPROGRAMUNIFORM4FPROC                               ProgramUniform4f;
		PFNGLPROGRAMUNIFORM4FVPROC                              ProgramUniform4fv;
		PFNGLPROGRAMUNIFORM4IPROC                               ProgramUniform4i;
		PFNGLPROGRAMUNIFORM4IVPROC                              ProgramUniform4iv;
		PFNGLPROGRAMUNIFORM4UIPROC                              ProgramUniform4ui;
		PFNGLPROGRAMUNIFORM4UIVPROC                             ProgramUniform4uiv;
		PFNGLPROGRAMUNIFORMMATRIX2DVPROC                        ProgramUniformMatrix2dv;
		PFNGLPROGRAMUNIFORMMATRIX2FVPROC                        ProgramUniformMatrix2fv;
		PFNGLPROGRAMUNIFORMMATRIX2X3DVPROC                      ProgramUniformMatrix2x3dv;
		PFNGLPROGRAMUNIFORMMATRIX2X3FVPROC                      ProgramUniformMatrix2x3fv;
		PFNGLPROGRAMUNIFORMMATRIX2X4DVPROC                      ProgramUniformMatrix2x4dv;
		PFNGLPROGRAMUNIFORMMATRIX2X4FVPROC                      ProgramUniformMatrix2x4fv;
		PFNGLPROGRAMUNIFORMMATRIX3DVPROC                        ProgramUniformMatrix3dv;
		PFNGLPROGRAMUNIFORMMATRIX3FVPROC                        ProgramUniformMatrix3fv;
		PFNGLPROGRAMUNIFORMMATRIX3X2DVPROC                      ProgramUniformMatrix3x2dv;
		PFNGLPROGRAMUNIFORMMATRIX3X2FVPROC                      ProgramUniformMatrix3x2fv;
		PFNGLPROGRAMUNIFORMMATRIX3X4DVPROC                      ProgramUniformMatrix3x4dv;
		PFNGLPROGRAMUNIFORMMATRIX3X4FVPROC                      ProgramUniformMatrix3x4fv;
		PFNGLPROGRAMUNIFORMMATRIX4DVPROC                        ProgramUniformMatrix4dv;
		PFNGLPROGRAMUNIFORMMATRIX4FVPROC                        ProgramUniformMatrix4fv;
		PFNGLPROGRAMUNIFORMMATRIX4X2DVPROC                      ProgramUniformMatrix4x2dv;
		PFNGLPROGRAMUNIFORMMATRIX4X2FVPROC                      ProgramUniformMatrix4x2fv;
		PFNGLPROGRAMUNIFORMMATRIX4X3DVPROC                      ProgramUniformMatrix4x3dv;
		PFNGLPROGRAMUNIFORMMATRIX4X3FVPROC                      ProgramUniformMatrix4x3fv;
		PFNGLPROVOKINGVERTEXPROC                                ProvokingVertex;
		PFNGLPUSHDEBUGGROUPPROC                                 PushDebugGroup;
		PFNGLQUERYCOUNTERPROC                                   QueryCounter;
		PFNGLREADBUFFERPROC                                     ReadBuffer;
		PFNGLREADPIXELSPROC                                     ReadPixels;
		PFNGLRELEASESHADERCOMPILERPROC                          ReleaseShaderCompiler;
		PFNGLRENDERBUFFERSTORAGEPROC                            RenderbufferStorage;
		PFNGLRENDERBUFFERSTORAGEMULTISAMPLEPROC                 RenderbufferStorageMultisample;
		PFNGLRESUMETRANSFORMFEEDBACKPROC                        ResumeTransformFeedback;
		PFNGLSAMPLECOVERAGEPROC                                 SampleCoverage;
		PFNGLSAMPLEMASKIPROC                                    SampleMaski;
		PFNGLSAMPLERPARAMETERIIVPROC                            SamplerParameterIiv;
		PFNGLSAMPLERPARAMETERIUIVPROC                           SamplerParameterIuiv;
		PFNGLSAMPLERPARAMETERFPROC                              SamplerParameterf;
		PFNGLSAMPLERPARAMETERFVPROC                             SamplerParameterfv;
		PFNGLSAMPLERPARAMETERIPROC                              SamplerParameteri;
		PFNGLSAMPLERPARAMETERIVPROC                             SamplerParameteriv;
		PFNGLSCISSORPROC                                        Scissor;
		PFNGLSCISSORARRAYVPROC                                  ScissorArrayv;
		PFNGLSCISSORINDEXEDPROC                                 ScissorIndexed;
		PFNGLSCISSORINDEXEDVPROC                                ScissorIndexedv;
		PFNGLSECONDARYCOLORP3UIPROC                             SecondaryColorP3ui;
		PFNGLSECONDARYCOLORP3UIVPROC                            SecondaryColorP3uiv;
		PFNGLSHADERBINARYPROC                                   ShaderBinary;
		PFNGLSHADERSOURCEPROC                                   ShaderSource;
		PFNGLSHADERSTORAGEBLOCKBINDINGPROC                      ShaderStorageBlockBinding;
		PFNGLSTENCILFUNCPROC                                    StencilFunc;
		PFNGLSTENCILFUNCSEPARATEPROC                            StencilFuncSeparate;
		PFNGLSTENCILMASKPROC                                    StencilMask;
		PFNGLSTENCILMASKSEPARATEPROC                            StencilMaskSeparate;
		PFNGLSTENCILOPPROC                                      StencilOp;
		PFNGLSTENCILOPSEPARATEPROC                              StencilOpSeparate;
		PFNGLTEXBUFFERPROC                                      TexBuffer;
		PFNGLTEXBUFFERRANGEPROC                                 TexBufferRange;
		PFNGLTEXCOORDP1UIPROC                                   TexCoordP1ui;
		PFNGLTEXCOORDP1UIVPROC                                  TexCoordP1uiv;
		PFNGLTEXCOORDP2UIPROC                                   TexCoordP2ui;
		PFNGLTEXCOORDP2UIVPROC                                  TexCoordP2uiv;
		PFNGLTEXCOORDP3UIPROC                                   TexCoordP3ui;
		PFNGLTEXCOORDP3UIVPROC                                  TexCoordP3uiv;
		PFNGLTEXCOORDP4UIPROC                                   TexCoordP4ui;
		PFNGLTEXCOORDP4UIVPROC                                  TexCoordP4uiv;
		PFNGLTEXIMAGE1DPROC                                     TexImage1D;
		PFNGLTEXIMAGE2DPROC                                     TexImage2D;
		PFNGLTEXIMAGE2DMULTISAMPLEPROC                          TexImage2DMultisample;
		PFNGLTEXIMAGE3DPROC                                     TexImage3D;
		PFNGLTEXIMAGE3DMULTISAMPLEPROC                          TexImage3DMultisample;
		PFNGLTEXPARAMETERIIVPROC                                TexParameterIiv;
		PFNGLTEXPARAMETERIUIVPROC                               TexParameterIuiv;
		PFNGLTEXPARAMETERFPROC                                  TexParameterf;
		PFNGLTEXPARAMETERFVPROC                                 TexParameterfv;
		PFNGLTEXPARAMETERIPROC                                  TexParameteri;
		PFNGLTEXPARAMETERIVPROC                                 TexParameteriv;
		PFNGLTEXSTORAGE1DPROC                                   TexStorage1D;
		PFNGLTEXSTORAGE2DPROC                                   TexStorage2D;
		PFNGLTEXSTORAGE2DMULTISAMPLEPROC                        TexStorage2DMultisample;
		PFNGLTEXSTORAGE3DPROC                                   TexStorage3D;
		PFNGLTEXSTORAGE3DMULTISAMPLEPROC                        TexStorage3DMultisample;
		PFNGLTEXSUBIMAGE1DPROC                                  TexSubImage1D;
		PFNGLTEXSUBIMAGE2DPROC                                  TexSubImage2D;
		PFNGLTEXSUBIMAGE3DPROC                                  TexSubImage3D;
		PFNGLTEXTUREVIEWPROC                                    TextureView;
		PFNGLTRANSFORMFEEDBACKVARYINGSPROC                      TransformFeedbackVaryings;
		PFNGLUNIFORM1DPROC                                      Uniform1d;
		PFNGLUNIFORM1DVPROC                                     Uniform1dv;
		PFNGLUNIFORM1FPROC                                      Uniform1f;
		PFNGLUNIFORM1FVPROC                                     Uniform1fv;
		PFNGLUNIFORM1IPROC                                      Uniform1i;
		PFNGLUNIFORM1IVPROC                                     Uniform1iv;
		PFNGLUNIFORM1UIPROC                                     Uniform1ui;
		PFNGLUNIFORM1UIVPROC                                    Uniform1uiv;
		PFNGLUNIFORM2DPROC                                      Uniform2d;
		PFNGLUNIFORM2DVPROC                                     Uniform2dv;
		PFNGLUNIFORM2FPROC                                      Uniform2f;
		PFNGLUNIFORM2FVPROC                                     Uniform2fv;
		PFNGLUNIFORM2IPROC                                      Uniform2i;
		PFNGLUNIFORM2IVPROC                                     Uniform2iv;
		PFNGLUNIFORM2UIPROC                                     Uniform2ui;
		PFNGLUNIFORM2UIVPROC                                    Uniform2uiv;
		PFNGLUNIFORM3DPROC                                      Uniform3d;
		PFNGLUNIFORM3DVPROC                                     Uniform3dv;
		PFNGLUNIFORM3FPROC                                      Uniform3f;
		PFNGLUNIFORM3FVPROC                                     Uniform3fv;
		PFNGLUNIFORM3IPROC                                      Uniform3i;
		PFNGLUNIFORM3IVPROC                                     Uniform3iv;
		PFNGLUNIFORM3UIPROC                                     Uniform3ui;
		PFNGLUNIFORM3UIVPROC                                    Uniform3uiv;
		PFNGLUNIFORM4DPROC                                      Uniform4d;
		PFNGLUNIFORM4DVPROC                                     Uniform4dv;
		PFNGLUNIFORM4FPROC                                      Uniform4f;
		PFNGLUNIFORM4FVPROC                                     Uniform4fv;
		PFNGLUNIFORM4IPROC                                      Uniform4i;
		PFNGLUNIFORM4IVPROC                                     Uniform4iv;
		PFNGLUNIFORM4UIPROC                                     Uniform4ui;
		PFNGLUNIFORM4UIVPROC                                    Uniform4uiv;
		PFNGLUNIFORMBLOCKBINDINGPROC                            UniformBlockBinding;
		PFNGLUNIFORMMATRIX2DVPROC                               UniformMatrix2dv;
		PFNGLUNIFORMMATRIX2FVPROC                               UniformMatrix2fv;
		PFNGLUNIFORMMATRIX2X3DVPROC                             UniformMatrix2x3dv;
		PFNGLUNIFORMMATRIX2X3FVPROC                             UniformMatrix2x3fv;
		PFNGLUNIFORMMATRIX2X4DVPROC                             UniformMatrix2x4dv;
		PFNGLUNIFORMMATRIX2X4FVPROC                             UniformMatrix2x4fv;
		PFNGLUNIFORMMATRIX3DVPROC                               UniformMatrix3dv;
		PFNGLUNIFORMMATRIX3FVPROC                               UniformMatrix3fv;
		PFNGLUNIFORMMATRIX3X2DVPROC                             UniformMatrix3x2dv;
		PFNGLUNIFORMMATRIX3X2FVPROC                             UniformMatrix3x2fv;
		PFNGLUNIFORMMATRIX3X4DVPROC                             UniformMatrix3x4dv;
		PFNGLUNIFORMMATRIX3X4FVPROC                             UniformMatrix3x4fv;
		PFNGLUNIFORMMATRIX4DVPROC                               UniformMatrix4dv;
		PFNGLUNIFORMMATRIX4FVPROC                               UniformMatrix4fv;
		PFNGLUNIFORMMATRIX4X2DVPROC                             UniformMatrix4x2dv;
		PFNGLUNIFORMMATRIX4X2FVPROC                             UniformMatrix4x2fv;
		PFNGLUNIFORMMATRIX4X3DVPROC                             UniformMatrix4x3dv;
		PFNGLUNIFORMMATRIX4X3FVPROC                             UniformMatrix4x3fv;
		PFNGLUNIFORMSUBROUTINESUIVPROC                          UniformSubroutinesuiv;
		PFNGLUNMAPBUFFERPROC                                    UnmapBuffer;
		PFNGLUSEPROGRAMPROC                                     UseProgram;
		PFNGLUSEPROGRAMSTAGESPROC                               UseProgramStages;
		PFNGLVALIDATEPROGRAMPROC                                ValidateProgram;
		PFNGLVALIDATEPROGRAMPIPELINEPROC                        ValidateProgramPipeline;
		PFNGLVERTEXATTRIB1DPROC                                 VertexAttrib1d;
		PFNGLVERTEXATTRIB1DVPROC                                VertexAttrib1dv;
		PFNGLVERTEXATTRIB1FPROC                                 VertexAttrib1f;
		PFNGLVERTEXATTRIB1FVPROC                                VertexAttrib1fv;
		PFNGLVERTEXATTRIB1SPROC                                 VertexAttrib1s;
		PFNGLVERTEXATTRIB1SVPROC                                VertexAttrib1sv;
		PFNGLVERTEXATTRIB2DPROC                                 VertexAttrib2d;
		PFNGLVERTEXATTRIB2DVPROC                                VertexAttrib2dv;
		PFNGLVERTEXATTRIB2FPROC                                 VertexAttrib2f;
		PFNGLVERTEXATTRIB2FVPROC                                VertexAttrib2fv;
		PFNGLVERTEXATTRIB2SPROC                                 VertexAttrib2s;
		PFNGLVERTEXATTRIB2SVPROC                                VertexAttrib2sv;
		PFNGLVERTEXATTRIB3DPROC                                 VertexAttrib3d;
		PFNGLVERTEXATTRIB3DVPROC                                VertexAttrib3dv;
		PFNGLVERTEXATTRIB3FPROC                                 VertexAttrib3f;
		PFNGLVERTEXATTRIB3FVPROC                                VertexAttrib3fv;
		PFNGLVERTEXATTRIB3SPROC                                 VertexAttrib3s;
		PFNGLVERTEXATTRIB3SVPROC                                VertexAttrib3sv;
		PFNGLVERTEXATTRIB4NBVPROC                               VertexAttrib4Nbv;
		PFNGLVERTEXATTRIB4NIVPROC                               VertexAttrib4Niv;
		PFNGLVERTEXATTRIB4NSVPROC                               VertexAttrib4Nsv;
		PFNGLVERTEXATTRIB4NUBPROC                               VertexAttrib4Nub;
		PFNGLVERTEXATTRIB4NUBVPROC                              VertexAttrib4Nubv;
		PFNGLVERTEXATTRIB4NUIVPROC                              VertexAttrib4Nuiv;
		PFNGLVERTEXATTRIB4NUSVPROC                              VertexAttrib4Nusv;
		PFNGLVERTEXATTRIB4BVPROC                                VertexAttrib4bv;
		PFNGLVERTEXATTRIB4DPROC                                 VertexAttrib4d;
		PFNGLVERTEXATTRIB4DVPROC                                VertexAttrib4dv;
		PFNGLVERTEXATTRIB4FPROC                                 VertexAttrib4f;
		PFNGLVERTEXATTRIB4FVPROC                                VertexAttrib4fv;
		PFNGLVERTEXATTRIB4IVPROC                                VertexAttrib4iv;
		PFNGLVERTEXATTRIB4SPROC                                 VertexAttrib4s;
		PFNGLVERTEXATTRIB4SVPROC                                VertexAttrib4sv;
		PFNGLVERTEXATTRIB4UBVPROC                               VertexAttrib4ubv;
		PFNGLVERTEXATTRIB4UIVPROC                               VertexAttrib4uiv;
		PFNGLVERTEXATTRIB4USVPROC                               VertexAttrib4usv;
		PFNGLVERTEXATTRIBBINDINGPROC                            VertexAttribBinding;
		PFNGLVERTEXATTRIBDIVISORPROC                            VertexAttribDivisor;
		PFNGLVERTEXATTRIBFORMATPROC                             VertexAttribFormat;
		PFNGLVERTEXATTRIBI1IPROC                                VertexAttribI1i;
		PFNGLVERTEXATTRIBI1IVPROC                               VertexAttribI1iv;
		PFNGLVERTEXATTRIBI1UIPROC                               VertexAttribI1ui;
		PFNGLVERTEXATTRIBI1UIVPROC                              VertexAttribI1uiv;
		PFNGLVERTEXATTRIBI2IPROC                                VertexAttribI2i;
		PFNGLVERTEXATTRIBI2IVPROC                               VertexAttribI2iv;
		PFNGLVERTEXATTRIBI2UIPROC                               VertexAttribI2ui;
		PFNGLVERTEXATTRIBI2UIVPROC                              VertexAttribI2uiv;
		PFNGLVERTEXATTRIBI3IPROC                                VertexAttribI3i;
		PFNGLVERTEXATTRIBI3IVPROC                               VertexAttribI3iv;
		PFNGLVERTEXATTRIBI3UIPROC                               VertexAttribI3ui;
		PFNGLVERTEXATTRIBI3UIVPROC                              VertexAttribI3uiv;
		PFNGLVERTEXATTRIBI4BVPROC                               VertexAttribI4bv;
		PFNGLVERTEXATTRIBI4IPROC                                VertexAttribI4i;
		PFNGLVERTEXATTRIBI4IVPROC                               VertexAttribI4iv;
		PFNGLVERTEXATTRIBI4SVPROC                               VertexAttribI4sv;
		PFNGLVERTEXATTRIBI4UBVPROC                              VertexAttribI4ubv;
		PFNGLVERTEXATTRIBI4UIPROC                               VertexAttribI4ui;
		PFNGLVERTEXATTRIBI4UIVPROC                              VertexAttribI4uiv;
		PFNGLVERTEXATTRIBI4USVPROC                              VertexAttribI4usv;
		PFNGLVERTEXATTRIBIFORMATPROC                            VertexAttribIFormat;
		PFNGLVERTEXATTRIBIPOINTERPROC                           VertexAttribIPointer;
		PFNGLVERTEXATTRIBL1DPROC                                VertexAttribL1d;
		PFNGLVERTEXATTRIBL1DVPROC                               VertexAttribL1dv;
		PFNGLVERTEXATTRIBL2DPROC                                VertexAttribL2d;
		PFNGLVERTEXATTRIBL2DVPROC                               VertexAttribL2dv;
		PFNGLVERTEXATTRIBL3DPROC                                VertexAttribL3d;
		PFNGLVERTEXATTRIBL3DVPROC                               VertexAttribL3dv;
		PFNGLVERTEXATTRIBL4DPROC                                VertexAttribL4d;
		PFNGLVERTEXATTRIBL4DVPROC                               VertexAttribL4dv;
		PFNGLVERTEXATTRIBLFORMATPROC                            VertexAttribLFormat;
		PFNGLVERTEXATTRIBLPOINTERPROC                           VertexAttribLPointer;
		PFNGLVERTEXATTRIBP1UIPROC                               VertexAttribP1ui;
		PFNGLVERTEXATTRIBP1UIVPROC                              VertexAttribP1uiv;
		PFNGLVERTEXATTRIBP2UIPROC                               VertexAttribP2ui;
		PFNGLVERTEXATTRIBP2UIVPROC                              VertexAttribP2uiv;
		PFNGLVERTEXATTRIBP3UIPROC                               VertexAttribP3ui;
		PFNGLVERTEXATTRIBP3UIVPROC                              VertexAttribP3uiv;
		PFNGLVERTEXATTRIBP4UIPROC                               VertexAttribP4ui;
		PFNGLVERTEXATTRIBP4UIVPROC                              VertexAttribP4uiv;
		PFNGLVERTEXATTRIBPOINTERPROC                            VertexAttribPointer;
		PFNGLVERTEXBINDINGDIVISORPROC                           VertexBindingDivisor;
		PFNGLVERTEXP2UIPROC                                     VertexP2ui;
		PFNGLVERTEXP2UIVPROC                                    VertexP2uiv;
		PFNGLVERTEXP3UIPROC                                     VertexP3ui;
		PFNGLVERTEXP3UIVPROC                                    VertexP3uiv;
		PFNGLVERTEXP4UIPROC                                     VertexP4ui;
		PFNGLVERTEXP4UIVPROC                                    VertexP4uiv;
		PFNGLVIEWPORTPROC                                       Viewport;
		PFNGLVIEWPORTARRAYVPROC                                 ViewportArrayv;
		PFNGLVIEWPORTINDEXEDFPROC                               ViewportIndexedf;
		PFNGLVIEWPORTINDEXEDFVPROC                              ViewportIndexedfv;
		PFNGLWAITSYNCPROC                                       WaitSync;
	} gl;
};
GL3W_API extern union GL3WProcs gl3wProcs;
/* OpenGL functions */
#define glActiveShaderProgram                            gl3wProcs.gl.ActiveShaderProgram
#define glActiveTexture                                  gl3wProcs.gl.ActiveTexture
#define glAttachShader                                   gl3wProcs.gl.AttachShader
#define glBeginConditionalRender                         gl3wProcs.gl.BeginConditionalRender
#define glBeginQuery                                     gl3wProcs.gl.BeginQuery
#define glBeginQueryIndexed                              gl3wProcs.gl.BeginQueryIndexed
#define glBeginTransformFeedback                         gl3wProcs.gl.BeginTransformFeedback
#define glBindAttribLocation                             gl3wProcs.gl.BindAttribLocation
#define glBindBuffer                                     gl3wProcs.gl.BindBuffer
#define glBindBufferBase                                 gl3wProcs.gl.BindBufferBase
#define glBindBufferRange                                gl3wProcs.gl.BindBufferRange
#define glBindFragDataLocation                           gl3wProcs.gl.BindFragDataLocation
#define glBindFragDataLocationIndexed                    gl3wProcs.gl.BindFragDataLocationIndexed
#define glBindFramebuffer                                gl3wProcs.gl.BindFramebuffer
#define glBindImageTexture                               gl3wProcs.gl.BindImageTexture
#define glBindProgramPipeline                            gl3wProcs.gl.BindProgramPipeline
#define glBindRenderbuffer                               gl3wProcs.gl.BindRenderbuffer
#define glBindSampler                                    gl3wProcs.gl.BindSampler
#define glBindTexture                                    gl3wProcs.gl.BindTexture
#define glBindTransformFeedback                          gl3wProcs.gl.BindTransformFeedback
#define glBindVertexArray                                gl3wProcs.gl.BindVertexArray
#define glBindVertexBuffer                               gl3wProcs.gl.BindVertexBuffer
#define glBlendColor                                     gl3wProcs.gl.BlendColor
#define glBlendEquation                                  gl3wProcs.gl.BlendEquation
#define glBlendEquationSeparate                          gl3wProcs.gl.BlendEquationSeparate
#define glBlendEquationSeparatei                         gl3wProcs.gl.BlendEquationSeparatei
#define glBlendEquationi                                 gl3wProcs.gl.BlendEquationi
#define glBlendFunc                                      gl3wProcs.gl.BlendFunc
#define glBlendFuncSeparate                              gl3wProcs.gl.BlendFuncSeparate
#define glBlendFuncSeparatei                             gl3wProcs.gl.BlendFuncSeparatei
#define glBlendFunci                                     gl3wProcs.gl.BlendFunci
#define glBlitFramebuffer                                gl3wProcs.gl.BlitFramebuffer
#define glBufferData                                     gl3wProcs.gl.BufferData
#define glBufferStorage                                  gl3wProcs.gl.BufferStorage
#define glBufferSubData                                  gl3wProcs.gl.BufferSubData
#define glCheckFramebufferStatus                         gl3wProcs.gl.CheckFramebufferStatus
#define glClampColor                                     gl3wProcs.gl.ClampColor
#define glClear                                          gl3wProcs.gl.Clear
#define glClearBufferData                                gl3wProcs.gl.ClearBufferData
#define glClearBufferSubData                             gl3wProcs.gl.ClearBufferSubData
#define glClearBufferfi                                  gl3wProcs.gl.ClearBufferfi
#define glClearBufferfv                                  gl3wProcs.gl.ClearBufferfv
#define glClearBufferiv                                  gl3wProcs.gl.ClearBufferiv
#define glClearBufferuiv                                 gl3wProcs.gl.ClearBufferuiv
#define glClearColor                                     gl3wProcs.gl.ClearColor
#define glClearDepth                                     gl3wProcs.gl.ClearDepth
#define glClearDepthf                                    gl3wProcs.gl.ClearDepthf
#define glClearStencil                                   gl3wProcs.gl.ClearStencil
#define glClientWaitSync                                 gl3wProcs.gl.ClientWaitSync
#define glColorMask                                      gl3wProcs.gl.ColorMask
#define glColorMaski                                     gl3wProcs.gl.ColorMaski
#define glColorP3ui                                      gl3wProcs.gl.ColorP3ui
#define glColorP3uiv                                     gl3wProcs.gl.ColorP3uiv
#define glColorP4ui                                      gl3wProcs.gl.ColorP4ui
#define glColorP4uiv                                     gl3wProcs.gl.ColorP4uiv
#define glCompileShader                                  gl3wProcs.gl.CompileShader
#define glCompressedTexImage1D                           gl3wProcs.gl.CompressedTexImage1D
#define glCompressedTexImage2D                           gl3wProcs.gl.CompressedTexImage2D
#define glCompressedTexImage3D                           gl3wProcs.gl.CompressedTexImage3D
#define glCompressedTexSubImage1D                        gl3wProcs.gl.CompressedTexSubImage1D
#define glCompressedTexSubImage2D                        gl3wProcs.gl.CompressedTexSubImage2D
#define glCompressedTexSubImage3D                        gl3wProcs.gl.CompressedTexSubImage3D
#define glCopyBufferSubData                              gl3wProcs.gl.CopyBufferSubData
#define glCopyImageSubData                               gl3wProcs.gl.CopyImageSubData
#define glCopyTexImage1D                                 gl3wProcs.gl.CopyTexImage1D
#define glCopyTexImage2D                                 gl3wProcs.gl.CopyTexImage2D
#define glCopyTexSubImage1D                              gl3wProcs.gl.CopyTexSubImage1D
#define glCopyTexSubImage2D                              gl3wProcs.gl.CopyTexSubImage2D
#define glCopyTexSubImage3D                              gl3wProcs.gl.CopyTexSubImage3D
#define glCreateProgram                                  gl3wProcs.gl.CreateProgram
#define glCreateShader                                   gl3wProcs.gl.CreateShader
#define glCreateShaderProgramv                           gl3wProcs.gl.CreateShaderProgramv
#define glCullFace                                       gl3wProcs.gl.CullFace
#define glDebugMessageCallback                           gl3wProcs.gl.DebugMessageCallback
#define glDebugMessageControl                            gl3wProcs.gl.DebugMessageControl
#define glDebugMessageInsert                             gl3wProcs.gl.DebugMessageInsert
#define glDeleteBuffers                                  gl3wProcs.gl.DeleteBuffers
#define glDeleteFramebuffers                             gl3wProcs.gl.DeleteFramebuffers
#define glDeleteProgram                                  gl3wProcs.gl.DeleteProgram
#define glDeleteProgramPipelines                         gl3wProcs.gl.DeleteProgramPipelines
#define glDeleteQueries                                  gl3wProcs.gl.DeleteQueries
#define glDeleteRenderbuffers                            gl3wProcs.gl.DeleteRenderbuffers
#define glDeleteSamplers                                 gl3wProcs.gl.DeleteSamplers
#define glDeleteShader                                   gl3wProcs.gl.DeleteShader
#define glDeleteSync                                     gl3wProcs.gl.DeleteSync
#define glDeleteTextures                                 gl3wProcs.gl.DeleteTextures
#define glDeleteTransformFeedbacks                       gl3wProcs.gl.DeleteTransformFeedbacks
#define glDeleteVertexArrays                             gl3wProcs.gl.DeleteVertexArrays
#define glDepthFunc                                      gl3wProcs.gl.DepthFunc
#define glDepthMask                                      gl3wProcs.gl.DepthMask
#define glDepthRange                                     gl3wProcs.gl.DepthRange
#define glDepthRangeArrayv                               gl3wProcs.gl.DepthRangeArrayv
#define glDepthRangeIndexed                              gl3wProcs.gl.DepthRangeIndexed
#define glDepthRangef                                    gl3wProcs.gl.DepthRangef
#define glDetachShader                                   gl3wProcs.gl.DetachShader
#define glDisable                                        gl3wProcs.gl.Disable
#define glDisableVertexAttribArray                       gl3wProcs.gl.DisableVertexAttribArray
#define glDisablei                                       gl3wProcs.gl.Disablei
#define glDispatchCompute                                gl3wProcs.gl.DispatchCompute
#define glDispatchComputeIndirect                        gl3wProcs.gl.DispatchComputeIndirect
#define glDrawArrays                                     gl3wProcs.gl.DrawArrays
#define glDrawArraysIndirect                             gl3wProcs.gl.DrawArraysIndirect
#define glDrawArraysInstanced                            gl3wProcs.gl.DrawArraysInstanced
#define glDrawArraysInstancedBaseInstance                gl3wProcs.gl.DrawArraysInstancedBaseInstance
#define glDrawBuffer                                     gl3wProcs.gl.DrawBuffer
#define glDrawBuffers                                    gl3wProcs.gl.DrawBuffers
#define glDrawElements                                   gl3wProcs.gl.DrawElements
#define glDrawElementsBaseVertex                         gl3wProcs.gl.DrawElementsBaseVertex
#define glDrawElementsIndirect                           gl3wProcs.gl.DrawElementsIndirect
#define glDrawElementsInstanced                          gl3wProcs.gl.DrawElementsInstanced
#define glDrawElementsInstancedBaseInstance              gl3wProcs.gl.DrawElementsInstancedBaseInstance
#define glDrawElementsInstancedBaseVertex                gl3wProcs.gl.DrawElementsInstancedBaseVertex
#define glDrawElementsInstancedBaseVertexBaseInstance    gl3wProcs.gl.DrawElementsInstancedBaseVertexBaseInstance
#define glDrawRangeElements                              gl3wProcs.gl.DrawRangeElements
#define glDrawRangeElementsBaseVertex                    gl3wProcs.gl.DrawRangeElementsBaseVertex
#define glDrawTransformFeedback                          gl3wProcs.gl.DrawTransformFeedback
#define glDrawTransformFeedbackInstanced                 gl3wProcs.gl.DrawTransformFeedbackInstanced
#define glDrawTransformFeedbackStream                    gl3wProcs.gl.DrawTransformFeedbackStream
#define glDrawTransformFeedbackStreamInstanced           gl3wProcs.gl.DrawTransformFeedbackStreamInstanced
#define glEnable                                         gl3wProcs.gl.Enable
#define glEnableVertexAttribArray                        gl3wProcs.gl.EnableVertexAttribArray
#define glEnablei                                        gl3wProcs.gl.Enablei
#define glEndConditionalRender                           gl3wProcs.gl.EndConditionalRender
#define glEndQuery                                       gl3wProcs.gl.EndQuery
#define glEndQueryIndexed                                gl3wProcs.gl.EndQueryIndexed
#define glEndTransformFeedback                           gl3wProcs.gl.EndTransformFeedback
#define glFenceSync                                      gl3wProcs.gl.FenceSync
#define glFinish                                         gl3wProcs.gl.Finish
#define glFlush                                          gl3wProcs.gl.Flush
#define glFlushMappedBufferRange                         gl3wProcs.gl.FlushMappedBufferRange
#define glFramebufferParameteri                          gl3wProcs.gl.FramebufferParameteri
#define glFramebufferRenderbuffer                        gl3wProcs.gl.FramebufferRenderbuffer
#define glFramebufferTexture                             gl3wProcs.gl.FramebufferTexture
#define glFramebufferTexture1D                           gl3wProcs.gl.FramebufferTexture1D
#define glFramebufferTexture2D                           gl3wProcs.gl.FramebufferTexture2D
#define glFramebufferTexture3D                           gl3wProcs.gl.FramebufferTexture3D
#define glFramebufferTextureLayer                        gl3wProcs.gl.FramebufferTextureLayer
#define glFrontFace                                      gl3wProcs.gl.FrontFace
#define glGenBuffers                                     gl3wProcs.gl.GenBuffers
#define glGenFramebuffers                                gl3wProcs.gl.GenFramebuffers
#define glGenProgramPipelines                            gl3wProcs.gl.GenProgramPipelines
#define glGenQueries                                     gl3wProcs.gl.GenQueries
#define glGenRenderbuffers                               gl3wProcs.gl.GenRenderbuffers
#define glGenSamplers                                    gl3wProcs.gl.GenSamplers
#define glGenTextures                                    gl3wProcs.gl.GenTextures
#define glGenTransformFeedbacks                          gl3wProcs.gl.GenTransformFeedbacks
#define glGenVertexArrays                                gl3wProcs.gl.GenVertexArrays
#define glGenerateMipmap                                 gl3wProcs.gl.GenerateMipmap
#define glGetActiveAtomicCounterBufferiv                 gl3wProcs.gl.GetActiveAtomicCounterBufferiv
#define glGetActiveAttrib                                gl3wProcs.gl.GetActiveAttrib
#define glGetActiveSubroutineName                        gl3wProcs.gl.GetActiveSubroutineName
#define glGetActiveSubroutineUniformName                 gl3wProcs.gl.GetActiveSubroutineUniformName
#define glGetActiveSubroutineUniformiv                   gl3wProcs.gl.GetActiveSubroutineUniformiv
#define glGetActiveUniform                               gl3wProcs.gl.GetActiveUniform
#define glGetActiveUniformBlockName                      gl3wProcs.gl.GetActiveUniformBlockName
#define glGetActiveUniformBlockiv                        gl3wProcs.gl.GetActiveUniformBlockiv
#define glGetActiveUniformName                           gl3wProcs.gl.GetActiveUniformName
#define glGetActiveUniformsiv                            gl3wProcs.gl.GetActiveUniformsiv
#define glGetAttachedShaders                             gl3wProcs.gl.GetAttachedShaders
#define glGetAttribLocation                              gl3wProcs.gl.GetAttribLocation
#define glGetBooleani_v                                  gl3wProcs.gl.GetBooleani_v
#define glGetBooleanv                                    gl3wProcs.gl.GetBooleanv
#define glGetBufferParameteri64v                         gl3wProcs.gl.GetBufferParameteri64v
#define glGetBufferParameteriv                           gl3wProcs.gl.GetBufferParameteriv
#define glGetBufferPointerv                              gl3wProcs.gl.GetBufferPointerv
#define glGetBufferSubData                               gl3wProcs.gl.GetBufferSubData
#define glGetCompressedTexImage                          gl3wProcs.gl.GetCompressedTexImage
#define glGetDebugMessageLog                             gl3wProcs.gl.GetDebugMessageLog
#define glGetDoublei_v                                   gl3wProcs.gl.GetDoublei_v
#define glGetDoublev                                     gl3wProcs.gl.GetDoublev
#define glGetError                                       gl3wProcs.gl.GetError
#define glGetFloati_v                                    gl3wProcs.gl.GetFloati_v
#define glGetFloatv                                      gl3wProcs.gl.GetFloatv
#define glGetFragDataIndex                               gl3wProcs.gl.GetFragDataIndex
#define glGetFragDataLocation                            gl3wProcs.gl.GetFragDataLocation
#define glGetFramebufferAttachmentParameteriv            gl3wProcs.gl.GetFramebufferAttachmentParameteriv
#define glGetFramebufferParameteriv                      gl3wProcs.gl.GetFramebufferParameteriv
#define glGetInteger64i_v                                gl3wProcs.gl.GetInteger64i_v
#define glGetInteger64v                                  gl3wProcs.gl.GetInteger64v
#define glGetIntegeri_v                                  gl3wProcs.gl.GetIntegeri_v
#define glGetIntegerv                                    gl3wProcs.gl.GetIntegerv
#define glGetInternalformati64v                          gl3wProcs.gl.GetInternalformati64v
#define glGetInternalformativ                            gl3wProcs.gl.GetInternalformativ
#define glGetMultisamplefv                               gl3wProcs.gl.GetMultisamplefv
#define glGetObjectLabel                                 gl3wProcs.gl.GetObjectLabel
#define glGetObjectPtrLabel                              gl3wProcs.gl.GetObjectPtrLabel
#define glGetPointerv                                    gl3wProcs.gl.GetPointerv
#define glGetProgramBinary                               gl3wProcs.gl.GetProgramBinary
#define glGetProgramInfoLog                              gl3wProcs.gl.GetProgramInfoLog
#define glGetProgramInterfaceiv                          gl3wProcs.gl.GetProgramInterfaceiv
#define glGetProgramPipelineInfoLog                      gl3wProcs.gl.GetProgramPipelineInfoLog
#define glGetProgramPipelineiv                           gl3wProcs.gl.GetProgramPipelineiv
#define glGetProgramResourceIndex                        gl3wProcs.gl.GetProgramResourceIndex
#define glGetProgramResourceLocation                     gl3wProcs.gl.GetProgramResourceLocation
#define glGetProgramResourceLocationIndex                gl3wProcs.gl.GetProgramResourceLocationIndex
#define glGetProgramResourceName                         gl3wProcs.gl.GetProgramResourceName
#define glGetProgramResourceiv                           gl3wProcs.gl.GetProgramResourceiv
#define glGetProgramStageiv                              gl3wProcs.gl.GetProgramStageiv
#define glGetProgramiv                                   gl3wProcs.gl.GetProgramiv
#define glGetQueryIndexediv                              gl3wProcs.gl.GetQueryIndexediv
#define glGetQueryObjecti64v                             gl3wProcs.gl.GetQueryObjecti64v
#define glGetQueryObjectiv                               gl3wProcs.gl.GetQueryObjectiv
#define glGetQueryObjectui64v                            gl3wProcs.gl.GetQueryObjectui64v
#define glGetQueryObjectuiv                              gl3wProcs.gl.GetQueryObjectuiv
#define glGetQueryiv                                     gl3wProcs.gl.GetQueryiv
#define glGetRenderbufferParameteriv                     gl3wProcs.gl.GetRenderbufferParameteriv
#define glGetSamplerParameterIiv                         gl3wProcs.gl.GetSamplerParameterIiv
#define glGetSamplerParameterIuiv                        gl3wProcs.gl.GetSamplerParameterIuiv
#define glGetSamplerParameterfv                          gl3wProcs.gl.GetSamplerParameterfv
#define glGetSamplerParameteriv                          gl3wProcs.gl.GetSamplerParameteriv
#define glGetShaderInfoLog                               gl3wProcs.gl.GetShaderInfoLog
#define glGetShaderPrecisionFormat                       gl3wProcs.gl.GetShaderPrecisionFormat
#define glGetShaderSource                                gl3wProcs.gl.GetShaderSource
#define glGetShaderiv                                    gl3wProcs.gl.GetShaderiv
#define glGetString                                      gl3wProcs.gl.GetString
#define glGetStringi                                     gl3wProcs.gl.GetStringi
#define glGetSubroutineIndex                             gl3wProcs.gl.GetSubroutineIndex
#define glGetSubroutineUniformLocation                   gl3wProcs.gl.GetSubroutineUniformLocation
#define glGetSynciv                                      gl3wProcs.gl.GetSynciv
#define glGetTexImage                                    gl3wProcs.gl.GetTexImage
#define glGetTexLevelParameterfv                         gl3wProcs.gl.GetTexLevelParameterfv
#define glGetTexLevelParameteriv                         gl3wProcs.gl.GetTexLevelParameteriv
#define glGetTexParameterIiv                             gl3wProcs.gl.GetTexParameterIiv
#define glGetTexParameterIuiv                            gl3wProcs.gl.GetTexParameterIuiv
#define glGetTexParameterfv                              gl3wProcs.gl.GetTexParameterfv
#define glGetTexParameteriv                              gl3wProcs.gl.GetTexParameteriv
#define glGetTransformFeedbackVarying                    gl3wProcs.gl.GetTransformFeedbackVarying
#define glGetUniformBlockIndex                           gl3wProcs.gl.GetUniformBlockIndex
#define glGetUniformIndices                              gl3wProcs.gl.GetUniformIndices
#define glGetUniformLocation                             gl3wProcs.gl.GetUniformLocation
#define glGetUniformSubroutineuiv                        gl3wProcs.gl.GetUniformSubroutineuiv
#define glGetUniformdv                                   gl3wProcs.gl.GetUniformdv
#define glGetUniformfv                                   gl3wProcs.gl.GetUniformfv
#define glGetUniformiv                                   gl3wProcs.gl.GetUniformiv
#define glGetUniformuiv                                  gl3wProcs.gl.GetUniformuiv
#define glGetVertexAttribIiv                             gl3wProcs.gl.GetVertexAttribIiv
#define glGetVertexAttribIuiv                            gl3wProcs.gl.GetVertexAttribIuiv
#define glGetVertexAttribLdv                             gl3wProcs.gl.GetVertexAttribLdv
#define glGetVertexAttribPointerv                        gl3wProcs.gl.GetVertexAttribPointerv
#define glGetVertexAttribdv                              gl3wProcs.gl.GetVertexAttribdv
#define glGetVertexAttribfv                              gl3wProcs.gl.GetVertexAttribfv
#define glGetVertexAttribiv                              gl3wProcs.gl.GetVertexAttribiv
#define glHint                                           gl3wProcs.gl.Hint
#define glInvalidateBufferData                           gl3wProcs.gl.InvalidateBufferData
#define glInvalidateBufferSubData                        gl3wProcs.gl.InvalidateBufferSubData
#define glInvalidateFramebuffer                          gl3wProcs.gl.InvalidateFramebuffer
#define glInvalidateSubFramebuffer                       gl3wProcs.gl.InvalidateSubFramebuffer
#define glInvalidateTexImage                             gl3wProcs.gl.InvalidateTexImage
#define glInvalidateTexSubImage                          gl3wProcs.gl.InvalidateTexSubImage
#define glIsBuffer                                       gl3wProcs.gl.IsBuffer
#define glIsEnabled                                      gl3wProcs.gl.IsEnabled
#define glIsEnabledi                                     gl3wProcs.gl.IsEnabledi
#define glIsFramebuffer                                  gl3wProcs.gl.IsFramebuffer
#define glIsProgram                                      gl3wProcs.gl.IsProgram
#define glIsProgramPipeline                              gl3wProcs.gl.IsProgramPipeline
#define glIsQuery                                        gl3wProcs.gl.IsQuery
#define glIsRenderbuffer                                 gl3wProcs.gl.IsRenderbuffer
#define glIsSampler                                      gl3wProcs.gl.IsSampler
#define glIsShader                                       gl3wProcs.gl.IsShader
#define glIsSync                                         gl3wProcs.gl.IsSync
#define glIsTexture                                      gl3wProcs.gl.IsTexture
#define glIsTransformFeedback                            gl3wProcs.gl.IsTransformFeedback
#define glIsVertexArray                                  gl3wProcs.gl.IsVertexArray
#define glLineWidth                                      gl3wProcs.gl.LineWidth
#define glLinkProgram                                    gl3wProcs.gl.LinkProgram
#define glLogicOp                                        gl3wProcs.gl.LogicOp
#define glMapBuffer                                      gl3wProcs.gl.MapBuffer
#define glMapBufferRange                                 gl3wProcs.gl.MapBufferRange
#define glMemoryBarrier                                  gl3wProcs.gl.MemoryBarrier
#define glMinSampleShading                               gl3wProcs.gl.MinSampleShading
#define glMultiDrawArrays                                gl3wProcs.gl.MultiDrawArrays
#define glMultiDrawArraysIndirect                        gl3wProcs.gl.MultiDrawArraysIndirect
#define glMultiDrawElements                              gl3wProcs.gl.MultiDrawElements
#define glMultiDrawElementsBaseVertex                    gl3wProcs.gl.MultiDrawElementsBaseVertex
#define glMultiDrawElementsIndirect                      gl3wProcs.gl.MultiDrawElementsIndirect
#define glMultiTexCoordP1ui                              gl3wProcs.gl.MultiTexCoordP1ui
#define glMultiTexCoordP1uiv                             gl3wProcs.gl.MultiTexCoordP1uiv
#define glMultiTexCoordP2ui                              gl3wProcs.gl.MultiTexCoordP2ui
#define glMultiTexCoordP2uiv                             gl3wProcs.gl.MultiTexCoordP2uiv
#define glMultiTexCoordP3ui                              gl3wProcs.gl.MultiTexCoordP3ui
#define glMultiTexCoordP3uiv                             gl3wProcs.gl.MultiTexCoordP3uiv
#define glMultiTexCoordP4ui                              gl3wProcs.gl.MultiTexCoordP4ui
#define glMultiTexCoordP4uiv                             gl3wProcs.gl.MultiTexCoordP4uiv
#define glNormalP3ui                                     gl3wProcs.gl.NormalP3ui
#define glNormalP3uiv                                    gl3wProcs.gl.NormalP3uiv
#define glObjectLabel                                    gl3wProcs.gl.ObjectLabel
#define glObjectPtrLabel                                 gl3wProcs.gl.ObjectPtrLabel
#define glPatchParameterfv                               gl3wProcs.gl.PatchParameterfv
#define glPatchParameteri                                gl3wProcs.gl.PatchParameteri
#define glPauseTransformFeedback                         gl3wProcs.gl.PauseTransformFeedback
#define glPixelStoref                                    gl3wProcs.gl.PixelStoref
#define glPixelStorei                                    gl3wProcs.gl.PixelStorei
#define glPointParameterf                                gl3wProcs.gl.PointParameterf
#define glPointParameterfv                               gl3wProcs.gl.PointParameterfv
#define glPointParameteri                                gl3wProcs.gl.PointParameteri
#define glPointParameteriv                               gl3wProcs.gl.PointParameteriv
#define glPointSize                                      gl3wProcs.gl.PointSize
#define glPolygonMode                                    gl3wProcs.gl.PolygonMode
#define glPolygonOffset                                  gl3wProcs.gl.PolygonOffset
#define glPopDebugGroup                                  gl3wProcs.gl.PopDebugGroup
#define glPrimitiveRestartIndex                          gl3wProcs.gl.PrimitiveRestartIndex
#define glProgramBinary                                  gl3wProcs.gl.ProgramBinary
#define glProgramParameteri                              gl3wProcs.gl.ProgramParameteri
#define glProgramUniform1d                               gl3wProcs.gl.ProgramUniform1d
#define glProgramUniform1dv                              gl3wProcs.gl.ProgramUniform1dv
#define glProgramUniform1f                               gl3wProcs.gl.ProgramUniform1f
#define glProgramUniform1fv                              gl3wProcs.gl.ProgramUniform1fv
#define glProgramUniform1i                               gl3wProcs.gl.ProgramUniform1i
#define glProgramUniform1iv                              gl3wProcs.gl.ProgramUniform1iv
#define glProgramUniform1ui                              gl3wProcs.gl.ProgramUniform1ui
#define glProgramUniform1uiv                             gl3wProcs.gl.ProgramUniform1uiv
#define glProgramUniform2d                               gl3wProcs.gl.ProgramUniform2d
#define glProgramUniform2dv                              gl3wProcs.gl.ProgramUniform2dv
#define glProgramUniform2f                               gl3wProcs.gl.ProgramUniform2f
#define glProgramUniform2fv                              gl3wProcs.gl.ProgramUniform2fv
#define glProgramUniform2i                               gl3wProcs.gl.ProgramUniform2i
#define glProgramUniform2iv                              gl3wProcs.gl.ProgramUniform2iv
#define glProgramUniform2ui                              gl3wProcs.gl.ProgramUniform2ui
#define glProgramUniform2uiv                             gl3wProcs.gl.ProgramUniform2uiv
#define glProgramUniform3d                               gl3wProcs.gl.ProgramUniform3d
#define glProgramUniform3dv                              gl3wProcs.gl.ProgramUniform3dv
#define glProgramUniform3f                               gl3wProcs.gl.ProgramUniform3f
#define glProgramUniform3fv                              gl3wProcs.gl.ProgramUniform3fv
#define glProgramUniform3i                               gl3wProcs.gl.ProgramUniform3i
#define glProgramUniform3iv                              gl3wProcs.gl.ProgramUniform3iv
#define glProgramUniform3ui                              gl3wProcs.gl.ProgramUniform3ui
#define glProgramUniform3uiv                             gl3wProcs.gl.ProgramUniform3uiv
#define glProgramUniform4d                               gl3wProcs.gl.ProgramUniform4d
#define glProgramUniform4dv                              gl3wProcs.gl.ProgramUniform4dv
#define glProgramUniform4f                               gl3wProcs.gl.ProgramUniform4f
#define glProgramUniform4fv                              gl3wProcs.gl.ProgramUniform4fv
#define glProgramUniform4i                               gl3wProcs.gl.ProgramUniform4i
#define glProgramUniform4iv                              gl3wProcs.gl.ProgramUniform4iv
#define glProgramUniform4ui                              gl3wProcs.gl.ProgramUniform4ui
#define glProgramUniform4uiv                             gl3wProcs.gl.ProgramUniform4uiv
#define glProgramUniformMatrix2dv                        gl3wProcs.gl.ProgramUniformMatrix2dv
#define glProgramUniformMatrix2fv                        gl3wProcs.gl.ProgramUniformMatrix2fv
#define glProgramUniformMatrix2x3dv                      gl3wProcs.gl.ProgramUniformMatrix2x3dv
#define glProgramUniformMatrix2x3fv                      gl3wProcs.gl.ProgramUniformMatrix2x3fv
#define glProgramUniformMatrix2x4dv                      gl3wProcs.gl.ProgramUniformMatrix2x4dv
#define glProgramUniformMatrix2x4fv                      gl3wProcs.gl.ProgramUniformMatrix2x4fv
#define glProgramUniformMatrix3dv                        gl3wProcs.gl.ProgramUniformMatrix3dv
#define glProgramUniformMatrix3fv                        gl3wProcs.gl.ProgramUniformMatrix3fv
#define glProgramUniformMatrix3x2dv                      gl3wProcs.gl.ProgramUniformMatrix3x2dv
#define glProgramUniformMatrix3x2fv                      gl3wProcs.gl.ProgramUniformMatrix3x2fv
#define glProgramUniformMatrix3x4dv                      gl3wProcs.gl.ProgramUniformMatrix3x4dv
#define glProgramUniformMatrix3x4fv                      gl3wProcs.gl.ProgramUniformMatrix3x4fv
#define glProgramUniformMatrix4dv                        gl3wProcs.gl.ProgramUniformMatrix4dv
#define glProgramUniformMatrix4fv                        gl3wProcs.gl.ProgramUniformMatrix4fv
#define glProgramUniformMatrix4x2dv                      gl3wProcs.gl.ProgramUniformMatrix4x2dv
#define glProgramUniformMatrix4x2fv                      gl3wProcs.gl.ProgramUniformMatrix4x2fv
#define glProgramUniformMatrix4x3dv                      gl3wProcs.gl.ProgramUniformMatrix4x3dv
#define glProgramUniformMatrix4x3fv                      gl3wProcs.gl.ProgramUniformMatrix4x3fv
#define glProvokingVertex                                gl3wProcs.gl.ProvokingVertex
#define glPushDebugGroup                                 gl3wProcs.gl.PushDebugGroup
#define glQueryCounter                                   gl3wProcs.gl.QueryCounter
#define glReadBuffer                                     gl3wProcs.gl.ReadBuffer
#define glReadPixels                                     gl3wProcs.gl.ReadPixels
#define glReleaseShaderCompiler                          gl3wProcs.gl.ReleaseShaderCompiler
#define glRenderbufferStorage                            gl3wProcs.gl.RenderbufferStorage
#define glRenderbufferStorageMultisample                 gl3wProcs.gl.RenderbufferStorageMultisample
#define glResumeTransformFeedback                        gl3wProcs.gl.ResumeTransformFeedback
#define glSampleCoverage                                 gl3wProcs.gl.SampleCoverage
#define glSampleMaski                                    gl3wProcs.gl.SampleMaski
#define glSamplerParameterIiv                            gl3wProcs.gl.SamplerParameterIiv
#define glSamplerParameterIuiv                           gl3wProcs.gl.SamplerParameterIuiv
#define glSamplerParameterf                              gl3wProcs.gl.SamplerParameterf
#define glSamplerParameterfv                             gl3wProcs.gl.SamplerParameterfv
#define glSamplerParameteri                              gl3wProcs.gl.SamplerParameteri
#define glSamplerParameteriv                             gl3wProcs.gl.SamplerParameteriv
#define glScissor                                        gl3wProcs.gl.Scissor
#define glScissorArrayv                                  gl3wProcs.gl.ScissorArrayv
#define glScissorIndexed                                 gl3wProcs.gl.ScissorIndexed
#define glScissorIndexedv                                gl3wProcs.gl.ScissorIndexedv
#define glSecondaryColorP3ui                             gl3wProcs.gl.SecondaryColorP3ui
#define glSecondaryColorP3uiv                            gl3wProcs.gl.SecondaryColorP3uiv
#define glShaderBinary                                   gl3wProcs.gl.ShaderBinary
#define glShaderSource                                   gl3wProcs.gl.ShaderSource
#define glShaderStorageBlockBinding                      gl3wProcs.gl.ShaderStorageBlockBinding
#define glStencilFunc                                    gl3wProcs.gl.StencilFunc
#define glStencilFuncSeparate                            gl3wProcs.gl.StencilFuncSeparate
#define glStencilMask                                    gl3wProcs.gl.StencilMask
#define glStencilMaskSeparate                            gl3wProcs.gl.StencilMaskSeparate
#define glStencilOp                                      gl3wProcs.gl.StencilOp
#define glStencilOpSeparate                              gl3wProcs.gl.StencilOpSeparate
#define glTexBuffer                                      gl3wProcs.gl.TexBuffer
#define glTexBufferRange                                 gl3wProcs.gl.TexBufferRange
#define glTexCoordP1ui                                   gl3wProcs.gl.TexCoordP1ui
#define glTexCoordP1uiv                                  gl3wProcs.gl.TexCoordP1uiv
#define glTexCoordP2ui                                   gl3wProcs.gl.TexCoordP2ui
#define glTexCoordP2uiv                                  gl3wProcs.gl.TexCoordP2uiv
#define glTexCoordP3ui                                   gl3wProcs.gl.TexCoordP3ui
#define glTexCoordP3uiv                                  gl3wProcs.gl.TexCoordP3uiv
#define glTexCoordP4ui                                   gl3wProcs.gl.TexCoordP4ui
#define glTexCoordP4uiv                                  gl3wProcs.gl.TexCoordP4uiv
#define glTexImage1D                                     gl3wProcs.gl.TexImage1D
#define glTexImage2D                                     gl3wProcs.gl.TexImage2D
#define glTexImage2DMultisample                          gl3wProcs.gl.TexImage2DMultisample
#define glTexImage3D                                     gl3wProcs.gl.TexImage3D
#define glTexImage3DMultisample                          gl3wProcs.gl.TexImage3DMultisample
#define glTexParameterIiv                                gl3wProcs.gl.TexParameterIiv
#define glTexParameterIuiv                               gl3wProcs.gl.TexParameterIuiv
#define glTexParameterf                                  gl3wProcs.gl.TexParameterf
#define glTexParameterfv                                 gl3wProcs.gl.TexParameterfv
#define glTexParameteri                                  gl3wProcs.gl.TexParameteri
#define glTexParameteriv                                 gl3wProcs.gl.TexParameteriv
#define glTexStorage1D                                   gl3wProcs.gl.TexStorage1D
#define glTexStorage2D                                   gl3wProcs.gl.TexStorage2D
#define glTexStorage2DMultisample                        gl3wProcs.gl.TexStorage2DMultisample
#define glTexStorage3D                                   gl3wProcs.gl.TexStorage3D
#define glTexStorage3DMultisample                        gl3wProcs.gl.TexStorage3DMultisample
#define glTexSubImage1D                                  gl3wProcs.gl.TexSubImage1D
#define glTexSubImage2D                                  gl3wProcs.gl.TexSubImage2D
#define glTexSubImage3D                                  gl3wProcs.gl.TexSubImage3D
#define glTextureView                                    gl3wProcs.gl.TextureView
#define glTransformFeedbackVaryings                      gl3wProcs.gl.TransformFeedbackVaryings
#define glUniform1d                                      gl3wProcs.gl.Uniform1d
#define glUniform1dv                                     gl3wProcs.gl.Uniform1dv
#define glUniform1f                                      gl3wProcs.gl.Uniform1f
#define glUniform1fv                                     gl3wProcs.gl.Uniform1fv
#define glUniform1i                                      gl3wProcs.gl.Uniform1i
#define glUniform1iv                                     gl3wProcs.gl.Uniform1iv
#define glUniform1ui                                     gl3wProcs.gl.Uniform1ui
#define glUniform1uiv                                    gl3wProcs.gl.Uniform1uiv
#define glUniform2d                                      gl3wProcs.gl.Uniform2d
#define glUniform2dv                                     gl3wProcs.gl.Uniform2dv
#define glUniform2f                                      gl3wProcs.gl.Uniform2f
#define glUniform2fv                                     gl3wProcs.gl.Uniform2fv
#define glUniform2i                                      gl3wProcs.gl.Uniform2i
#define glUniform2iv                                     gl3wProcs.gl.Uniform2iv
#define glUniform2ui                                     gl3wProcs.gl.Uniform2ui
#define glUniform2uiv                                    gl3wProcs.gl.Uniform2uiv
#define glUniform3d                                      gl3wProcs.gl.Uniform3d
#define glUniform3dv                                     gl3wProcs.gl.Uniform3dv
#define glUniform3f                                      gl3wProcs.gl.Uniform3f
#define glUniform3fv                                     gl3wProcs.gl.Uniform3fv
#define glUniform3i                                      gl3wProcs.gl.Uniform3i
#define glUniform3iv                                     gl3wProcs.gl.Uniform3iv
#define glUniform3ui                                     gl3wProcs.gl.Uniform3ui
#define glUniform3uiv                                    gl3wProcs.gl.Uniform3uiv
#define glUniform4d                                      gl3wProcs.gl.Uniform4d
#define glUniform4dv                                     gl3wProcs.gl.Uniform4dv
#define glUniform4f                                      gl3wProcs.gl.Uniform4f
#define glUniform4fv                                     gl3wProcs.gl.Uniform4fv
#define glUniform4i                                      gl3wProcs.gl.Uniform4i
#define glUniform4iv                                     gl3wProcs.gl.Uniform4iv
#define glUniform4ui                                     gl3wProcs.gl.Uniform4ui
#define glUniform4uiv                                    gl3wProcs.gl.Uniform4uiv
#define glUniformBlockBinding                            gl3wProcs.gl.UniformBlockBinding
#define glUniformMatrix2dv                               gl3wProcs.gl.UniformMatrix2dv
#define glUniformMatrix2fv                               gl3wProcs.gl.UniformMatrix2fv
#define glUniformMatrix2x3dv                             gl3wProcs.gl.UniformMatrix2x3dv
#define glUniformMatrix2x3fv                             gl3wProcs.gl.UniformMatrix2x3fv
#define glUniformMatrix2x4dv                             gl3wProcs.gl.UniformMatrix2x4dv
#define glUniformMatrix2x4fv                             gl3wProcs.gl.UniformMatrix2x4fv
#define glUniformMatrix3dv                               gl3wProcs.gl.UniformMatrix3dv
#define glUniformMatrix3fv                               gl3wProcs.gl.UniformMatrix3fv
#define glUniformMatrix3x2dv                             gl3wProcs.gl.UniformMatrix3x2dv
#define glUniformMatrix3x2fv                             gl3wProcs.gl.UniformMatrix3x2fv
#define glUniformMatrix3x4dv                             gl3wProcs.gl.UniformMatrix3x4dv
#define glUniformMatrix3x4fv                             gl3wProcs.gl.UniformMatrix3x4fv
#define glUniformMatrix4dv                               gl3wProcs.gl.UniformMatrix4dv
#define glUniformMatrix4fv                               gl3wProcs.gl.UniformMatrix4fv
#define glUniformMatrix4x2dv                             gl3wProcs.gl.UniformMatrix4x2dv
#define glUniformMatrix4x2fv                             gl3wProcs.gl.UniformMatrix4x2fv
#define glUniformMatrix4x3dv                             gl3wProcs.gl.UniformMatrix4x3dv
#define glUniformMatrix4x3fv                             gl3wProcs.gl.UniformMatrix4x3fv
#define glUniformSubroutinesuiv                          gl3wProcs.gl.UniformSubroutinesuiv
#define glUnmapBuffer                                    gl3wProcs.gl.UnmapBuffer
#define glUseProgram                                     gl3wProcs.gl.UseProgram
#define glUseProgramStages                               gl3wProcs.gl.UseProgramStages
#define glValidateProgram                                gl3wProcs.gl.ValidateProgram
#define glValidateProgramPipeline                        gl3wProcs.gl.ValidateProgramPipeline
#define glVertexAttrib1d                                 gl3wProcs.gl.VertexAttrib1d
#define glVertexAttrib1dv                                gl3wProcs.gl.VertexAttrib1dv
#define glVertexAttrib1f                                 gl3wProcs.gl.VertexAttrib1f
#define glVertexAttrib1fv                                gl3wProcs.gl.VertexAttrib1fv
#define glVertexAttrib1s                                 gl3wProcs.gl.VertexAttrib1s
#define glVertexAttrib1sv                                gl3wProcs.gl.VertexAttrib1sv
#define glVertexAttrib2d                                 gl3wProcs.gl.VertexAttrib2d
#define glVertexAttrib2dv                                gl3wProcs.gl.VertexAttrib2dv
#define glVertexAttrib2f                                 gl3wProcs.gl.VertexAttrib2f
#define glVertexAttrib2fv                                gl3wProcs.gl.VertexAttrib2fv
#define glVertexAttrib2s                                 gl3wProcs.gl.VertexAttrib2s
#define glVertexAttrib2sv                                gl3wProcs.gl.VertexAttrib2sv
#define glVertexAttrib3d                                 gl3wProcs.gl.VertexAttrib3d
#define glVertexAttrib3dv                                gl3wProcs.gl.VertexAttrib3dv
#define glVertexAttrib3f                                 gl3wProcs.gl.VertexAttrib3f
#define glVertexAttrib3fv                                gl3wProcs.gl.VertexAttrib3fv
#define glVertexAttrib3s                                 gl3wProcs.gl.VertexAttrib3s
#define glVertexAttrib3sv                                gl3wProcs.gl.VertexAttrib3sv
#define glVertexAttrib4Nbv                               gl3wProcs.gl.VertexAttrib4Nbv
#define glVertexAttrib4Niv                               gl3wProcs.gl.VertexAttrib4Niv
#define glVertexAttrib4Nsv                               gl3wProcs.gl.VertexAttrib4Nsv
#define glVertexAttrib4Nub                               gl3wProcs.gl.VertexAttrib4Nub
#define glVertexAttrib4Nubv                              gl3wProcs.gl.VertexAttrib4Nubv
#define glVertexAttrib4Nuiv                              gl3wProcs.gl.VertexAttrib4Nuiv
#define glVertexAttrib4Nusv                              gl3wProcs.gl.VertexAttrib4Nusv
#define glVertexAttrib4bv                                gl3wProcs.gl.VertexAttrib4bv
#define glVertexAttrib4d                                 gl3wProcs.gl.VertexAttrib4d
#define glVertexAttrib4dv                                gl3wProcs.gl.VertexAttrib4dv
#define glVertexAttrib4f                                 gl3wProcs.gl.VertexAttrib4f
#define glVertexAttrib4fv                                gl3wProcs.gl.VertexAttrib4fv
#define glVertexAttrib4iv                                gl3wProcs.gl.VertexAttrib4iv
#define glVertexAttrib4s                                 gl3wProcs.gl.VertexAttrib4s
#define glVertexAttrib4sv                                gl3wProcs.gl.VertexAttrib4sv
#define glVertexAttrib4ubv                               gl3wProcs.gl.VertexAttrib4ubv
#define glVertexAttrib4uiv                               gl3wProcs.gl.VertexAttrib4uiv
#define glVertexAttrib4usv                               gl3wProcs.gl.VertexAttrib4usv
#define glVertexAttribBinding                            gl3wProcs.gl.VertexAttribBinding
#define glVertexAttribDivisor                            gl3wProcs.gl.VertexAttribDivisor
#define glVertexAttribFormat                             gl3wProcs.gl.VertexAttribFormat
#define glVertexAttribI1i                                gl3wProcs.gl.VertexAttribI1i
#define glVertexAttribI1iv                               gl3wProcs.gl.VertexAttribI1iv
#define glVertexAttribI1ui                               gl3wProcs.gl.VertexAttribI1ui
#define glVertexAttribI1uiv                              gl3wProcs.gl.VertexAttribI1uiv
#define glVertexAttribI2i                                gl3wProcs.gl.VertexAttribI2i
#define glVertexAttribI2iv                               gl3wProcs.gl.VertexAttribI2iv
#define glVertexAttribI2ui                               gl3wProcs.gl.VertexAttribI2ui
#define glVertexAttribI2uiv                              gl3wProcs.gl.VertexAttribI2uiv
#define glVertexAttribI3i                                gl3wProcs.gl.VertexAttribI3i
#define glVertexAttribI3iv                               gl3wProcs.gl.VertexAttribI3iv
#define glVertexAttribI3ui                               gl3wProcs.gl.VertexAttribI3ui
#define glVertexAttribI3uiv                              gl3wProcs.gl.VertexAttribI3uiv
#define glVertexAttribI4bv                               gl3wProcs.gl.VertexAttribI4bv
#define glVertexAttribI4i                                gl3wProcs.gl.VertexAttribI4i
#define glVertexAttribI4iv                               gl3wProcs.gl.VertexAttribI4iv
#define glVertexAttribI4sv                               gl3wProcs.gl.VertexAttribI4sv
#define glVertexAttribI4ubv                              gl3wProcs.gl.VertexAttribI4ubv
#define glVertexAttribI4ui                               gl3wProcs.gl.VertexAttribI4ui
#define glVertexAttribI4uiv                              gl3wProcs.gl.VertexAttribI4uiv
#define glVertexAttribI4usv                              gl3wProcs.gl.VertexAttribI4usv
#define glVertexAttribIFormat                            gl3wProcs.gl.VertexAttribIFormat
#define glVertexAttribIPointer                           gl3wProcs.gl.VertexAttribIPointer
#define glVertexAttribL1d                                gl3wProcs.gl.VertexAttribL1d
#define glVertexAttribL1dv                               gl3wProcs.gl.VertexAttribL1dv
#define glVertexAttribL2d                                gl3wProcs.gl.VertexAttribL2d
#define glVertexAttribL2dv                               gl3wProcs.gl.VertexAttribL2dv
#define glVertexAttribL3d                                gl3wProcs.gl.VertexAttribL3d
#define glVertexAttribL3dv                               gl3wProcs.gl.VertexAttribL3dv
#define glVertexAttribL4d                                gl3wProcs.gl.VertexAttribL4d
#define glVertexAttribL4dv                               gl3wProcs.gl.VertexAttribL4dv
#define glVertexAttribLFormat                            gl3wProcs.gl.VertexAttribLFormat
#define glVertexAttribLPointer                           gl3wProcs.gl.VertexAttribLPointer
#define glVertexAttribP1ui                               gl3wProcs.gl.VertexAttribP1ui
#define glVertexAttribP1uiv                              gl3wProcs.gl.VertexAttribP1uiv
#define glVertexAttribP2ui                               gl3wProcs.gl.VertexAttribP2ui
#define glVertexAttribP2uiv                              gl3wProcs.gl.VertexAttribP2uiv
#define glVertexAttribP3ui                               gl3wProcs.gl.VertexAttribP3ui
#define glVertexAttribP3uiv                              gl3wProcs.gl.VertexAttribP3uiv
#define glVertexAttribP4ui                               gl3wProcs.gl.VertexAttribP4ui
#define glVertexAttribP4uiv                              gl3wProcs.gl.VertexAttribP4uiv
#define glVertexAttribPointer                            gl3wProcs.gl.VertexAttribPointer
#define glVertexBindingDivisor                           gl3wProcs.gl.VertexBindingDivisor
#define glVertexP2ui                                     gl3wProcs.gl.VertexP2ui
#define glVertexP2uiv                                    gl3wProcs.gl.VertexP2uiv
#define glVertexP3ui                                     gl3wProcs.gl.VertexP3ui
#define glVertexP3uiv                                    gl3wProcs.gl.VertexP3uiv
#define glVertexP4ui                                     gl3wProcs.gl.VertexP4ui
#define glVertexP4uiv                                    gl3wProcs.gl.VertexP4uiv
#define glViewport                                       gl3wProcs.gl.Viewport
#define glViewportArrayv                                 gl3wProcs.gl.ViewportArrayv
#define glViewportIndexedf                               gl3wProcs.gl.ViewportIndexedf
#define glViewportIndexedfv                              gl3wProcs.gl.ViewportIndexedfv
#define glWaitSync                                       gl3wProcs.gl.WaitSync

#ifdef __cplusplus
}
#endif
#endif
