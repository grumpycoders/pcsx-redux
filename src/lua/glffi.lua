--lualoader, R"EOF(--
--OpenGL binding, taken and modified from https://github.com/malkia/luajit-opencl

ffi.cdef[[
enum {
 GL_ACCUM                          = 0x0100,
 GL_LOAD                           = 0x0101,
 GL_RETURN                         = 0x0102,
 GL_MULT                           = 0x0103,
 GL_ADD                            = 0x0104,
 GL_NEVER                          = 0x0200,
 GL_LESS                           = 0x0201,
 GL_EQUAL                          = 0x0202,
 GL_LEQUAL                         = 0x0203,
 GL_GREATER                        = 0x0204,
 GL_NOTEQUAL                       = 0x0205,
 GL_GEQUAL                         = 0x0206,
 GL_ALWAYS                         = 0x0207,
 GL_CURRENT_BIT                    = 0x00000001,
 GL_POINT_BIT                      = 0x00000002,
 GL_LINE_BIT                       = 0x00000004,
 GL_POLYGON_BIT                    = 0x00000008,
 GL_POLYGON_STIPPLE_BIT            = 0x00000010,
 GL_PIXEL_MODE_BIT                 = 0x00000020,
 GL_LIGHTING_BIT                   = 0x00000040,
 GL_FOG_BIT                        = 0x00000080,
 GL_DEPTH_BUFFER_BIT               = 0x00000100,
 GL_ACCUM_BUFFER_BIT               = 0x00000200,
 GL_STENCIL_BUFFER_BIT             = 0x00000400,
 GL_VIEWPORT_BIT                   = 0x00000800,
 GL_TRANSFORM_BIT                  = 0x00001000,
 GL_ENABLE_BIT                     = 0x00002000,
 GL_COLOR_BUFFER_BIT               = 0x00004000,
 GL_HINT_BIT                       = 0x00008000,
 GL_EVAL_BIT                       = 0x00010000,
 GL_LIST_BIT                       = 0x00020000,
 GL_TEXTURE_BIT                    = 0x00040000,
 GL_SCISSOR_BIT                    = 0x00080000,
 GL_ALL_ATTRIB_BITS                = 0x000fffff,
 GL_POINTS                         = 0x0000,
 GL_LINES                          = 0x0001,
 GL_LINE_LOOP                      = 0x0002,
 GL_LINE_STRIP                     = 0x0003,
 GL_TRIANGLES                      = 0x0004,
 GL_TRIANGLE_STRIP                 = 0x0005,
 GL_TRIANGLE_FAN                   = 0x0006,
 GL_QUADS                          = 0x0007,
 GL_QUAD_STRIP                     = 0x0008,
 GL_POLYGON                        = 0x0009,
 GL_ZERO                           = 0,
 GL_ONE                            = 1,
 GL_SRC_COLOR                      = 0x0300,
 GL_ONE_MINUS_SRC_COLOR            = 0x0301,
 GL_SRC_ALPHA                      = 0x0302,
 GL_ONE_MINUS_SRC_ALPHA            = 0x0303,
 GL_DST_ALPHA                      = 0x0304,
 GL_ONE_MINUS_DST_ALPHA            = 0x0305,
 GL_DST_COLOR                      = 0x0306,
 GL_ONE_MINUS_DST_COLOR            = 0x0307,
 GL_SRC_ALPHA_SATURATE             = 0x0308,
 GL_TRUE                           = 1,
 GL_FALSE                          = 0,
 GL_CLIP_PLANE0                    = 0x3000,
 GL_CLIP_PLANE1                    = 0x3001,
 GL_CLIP_PLANE2                    = 0x3002,
 GL_CLIP_PLANE3                    = 0x3003,
 GL_CLIP_PLANE4                    = 0x3004,
 GL_CLIP_PLANE5                    = 0x3005,
 GL_BYTE                           = 0x1400,
 GL_UNSIGNED_BYTE                  = 0x1401,
 GL_SHORT                          = 0x1402,
 GL_UNSIGNED_SHORT                 = 0x1403,
 GL_INT                            = 0x1404,
 GL_UNSIGNED_INT                   = 0x1405,
 GL_FLOAT                          = 0x1406,
 GL_2_BYTES                        = 0x1407,
 GL_3_BYTES                        = 0x1408,
 GL_4_BYTES                        = 0x1409,
 GL_DOUBLE                         = 0x140A,
 GL_NONE                           = 0,
 GL_FRONT_LEFT                     = 0x0400,
 GL_FRONT_RIGHT                    = 0x0401,
 GL_BACK_LEFT                      = 0x0402,
 GL_BACK_RIGHT                     = 0x0403,
 GL_FRONT                          = 0x0404,
 GL_BACK                           = 0x0405,
 GL_LEFT                           = 0x0406,
 GL_RIGHT                          = 0x0407,
 GL_FRONT_AND_BACK                 = 0x0408,
 GL_AUX0                           = 0x0409,
 GL_AUX1                           = 0x040A,
 GL_AUX2                           = 0x040B,
 GL_AUX3                           = 0x040C,
 GL_NO_ERROR                       = 0,
 GL_INVALID_ENUM                   = 0x0500,
 GL_INVALID_VALUE                  = 0x0501,
 GL_INVALID_OPERATION              = 0x0502,
 GL_STACK_OVERFLOW                 = 0x0503,
 GL_STACK_UNDERFLOW                = 0x0504,
 GL_OUT_OF_MEMORY                  = 0x0505,
 GL_2D                             = 0x0600,
 GL_3D                             = 0x0601,
 GL_3D_COLOR                       = 0x0602,
 GL_3D_COLOR_TEXTURE               = 0x0603,
 GL_4D_COLOR_TEXTURE               = 0x0604,
 GL_PASS_THROUGH_TOKEN             = 0x0700,
 GL_POINT_TOKEN                    = 0x0701,
 GL_LINE_TOKEN                     = 0x0702,
 GL_POLYGON_TOKEN                  = 0x0703,
 GL_BITMAP_TOKEN                   = 0x0704,
 GL_DRAW_PIXEL_TOKEN               = 0x0705,
 GL_COPY_PIXEL_TOKEN               = 0x0706,
 GL_LINE_RESET_TOKEN               = 0x0707,
 GL_EXP                            = 0x0800,
 GL_EXP2                           = 0x0801,
 GL_CW                             = 0x0900,
 GL_CCW                            = 0x0901,
 GL_COEFF                          = 0x0A00,
 GL_ORDER                          = 0x0A01,
 GL_DOMAIN                         = 0x0A02,
 GL_CURRENT_COLOR                  = 0x0B00,
 GL_CURRENT_INDEX                  = 0x0B01,
 GL_CURRENT_NORMAL                 = 0x0B02,
 GL_CURRENT_TEXTURE_COORDS         = 0x0B03,
 GL_CURRENT_RASTER_COLOR           = 0x0B04,
 GL_CURRENT_RASTER_INDEX           = 0x0B05,
 GL_CURRENT_RASTER_TEXTURE_COORDS  = 0x0B06,
 GL_CURRENT_RASTER_POSITION        = 0x0B07,
 GL_CURRENT_RASTER_POSITION_VALID  = 0x0B08,
 GL_CURRENT_RASTER_DISTANCE        = 0x0B09,
 GL_POINT_SMOOTH                   = 0x0B10,
 GL_POINT_SIZE                     = 0x0B11,
 GL_POINT_SIZE_RANGE               = 0x0B12,
 GL_POINT_SIZE_GRANULARITY         = 0x0B13,
 GL_LINE_SMOOTH                    = 0x0B20,
 GL_LINE_WIDTH                     = 0x0B21,
 GL_LINE_WIDTH_RANGE               = 0x0B22,
 GL_LINE_WIDTH_GRANULARITY         = 0x0B23,
 GL_LINE_STIPPLE                   = 0x0B24,
 GL_LINE_STIPPLE_PATTERN           = 0x0B25,
 GL_LINE_STIPPLE_REPEAT            = 0x0B26,
 GL_LIST_MODE                      = 0x0B30,
 GL_MAX_LIST_NESTING               = 0x0B31,
 GL_LIST_BASE                      = 0x0B32,
 GL_LIST_INDEX                     = 0x0B33,
 GL_POLYGON_MODE                   = 0x0B40,
 GL_POLYGON_SMOOTH                 = 0x0B41,
 GL_POLYGON_STIPPLE                = 0x0B42,
 GL_EDGE_FLAG                      = 0x0B43,
 GL_CULL_FACE                      = 0x0B44,
 GL_CULL_FACE_MODE                 = 0x0B45,
 GL_FRONT_FACE                     = 0x0B46,
 GL_LIGHTING                       = 0x0B50,
 GL_LIGHT_MODEL_LOCAL_VIEWER       = 0x0B51,
 GL_LIGHT_MODEL_TWO_SIDE           = 0x0B52,
 GL_LIGHT_MODEL_AMBIENT            = 0x0B53,
 GL_SHADE_MODEL                    = 0x0B54,
 GL_COLOR_MATERIAL_FACE            = 0x0B55,
 GL_COLOR_MATERIAL_PARAMETER       = 0x0B56,
 GL_COLOR_MATERIAL                 = 0x0B57,
 GL_FOG                            = 0x0B60,
 GL_FOG_INDEX                      = 0x0B61,
 GL_FOG_DENSITY                    = 0x0B62,
 GL_FOG_START                      = 0x0B63,
 GL_FOG_END                        = 0x0B64,
 GL_FOG_MODE                       = 0x0B65,
 GL_FOG_COLOR                      = 0x0B66,
 GL_DEPTH_RANGE                    = 0x0B70,
 GL_DEPTH_TEST                     = 0x0B71,
 GL_DEPTH_WRITEMASK                = 0x0B72,
 GL_DEPTH_CLEAR_VALUE              = 0x0B73,
 GL_DEPTH_FUNC                     = 0x0B74,
 GL_ACCUM_CLEAR_VALUE              = 0x0B80,
 GL_STENCIL_TEST                   = 0x0B90,
 GL_STENCIL_CLEAR_VALUE            = 0x0B91,
 GL_STENCIL_FUNC                   = 0x0B92,
 GL_STENCIL_VALUE_MASK             = 0x0B93,
 GL_STENCIL_FAIL                   = 0x0B94,
 GL_STENCIL_PASS_DEPTH_FAIL        = 0x0B95,
 GL_STENCIL_PASS_DEPTH_PASS        = 0x0B96,
 GL_STENCIL_REF                    = 0x0B97,
 GL_STENCIL_WRITEMASK              = 0x0B98,
 GL_MATRIX_MODE                    = 0x0BA0,
 GL_NORMALIZE                      = 0x0BA1,
 GL_VIEWPORT                       = 0x0BA2,
 GL_MODELVIEW_STACK_DEPTH          = 0x0BA3,
 GL_PROJECTION_STACK_DEPTH         = 0x0BA4,
 GL_TEXTURE_STACK_DEPTH            = 0x0BA5,
 GL_MODELVIEW_MATRIX               = 0x0BA6,
 GL_PROJECTION_MATRIX              = 0x0BA7,
 GL_TEXTURE_MATRIX                 = 0x0BA8,
 GL_ATTRIB_STACK_DEPTH             = 0x0BB0,
 GL_CLIENT_ATTRIB_STACK_DEPTH      = 0x0BB1,
 GL_ALPHA_TEST                     = 0x0BC0,
 GL_ALPHA_TEST_FUNC                = 0x0BC1,
 GL_ALPHA_TEST_REF                 = 0x0BC2,
 GL_DITHER                         = 0x0BD0,
 GL_BLEND_DST                      = 0x0BE0,
 GL_BLEND_SRC                      = 0x0BE1,
 GL_BLEND                          = 0x0BE2,
 GL_LOGIC_OP_MODE                  = 0x0BF0,
 GL_INDEX_LOGIC_OP                 = 0x0BF1,
 GL_COLOR_LOGIC_OP                 = 0x0BF2,
 GL_AUX_BUFFERS                    = 0x0C00,
 GL_DRAW_BUFFER                    = 0x0C01,
 GL_READ_BUFFER                    = 0x0C02,
 GL_SCISSOR_BOX                    = 0x0C10,
 GL_SCISSOR_TEST                   = 0x0C11,
 GL_INDEX_CLEAR_VALUE              = 0x0C20,
 GL_INDEX_WRITEMASK                = 0x0C21,
 GL_COLOR_CLEAR_VALUE              = 0x0C22,
 GL_COLOR_WRITEMASK                = 0x0C23,
 GL_INDEX_MODE                     = 0x0C30,
 GL_RGBA_MODE                      = 0x0C31,
 GL_DOUBLEBUFFER                   = 0x0C32,
 GL_STEREO                         = 0x0C33,
 GL_RENDER_MODE                    = 0x0C40,
 GL_PERSPECTIVE_CORRECTION_HINT    = 0x0C50,
 GL_POINT_SMOOTH_HINT              = 0x0C51,
 GL_LINE_SMOOTH_HINT               = 0x0C52,
 GL_POLYGON_SMOOTH_HINT            = 0x0C53,
 GL_FOG_HINT                       = 0x0C54,
 GL_TEXTURE_GEN_S                  = 0x0C60,
 GL_TEXTURE_GEN_T                  = 0x0C61,
 GL_TEXTURE_GEN_R                  = 0x0C62,
 GL_TEXTURE_GEN_Q                  = 0x0C63,
 GL_PIXEL_MAP_I_TO_I               = 0x0C70,
 GL_PIXEL_MAP_S_TO_S               = 0x0C71,
 GL_PIXEL_MAP_I_TO_R               = 0x0C72,
 GL_PIXEL_MAP_I_TO_G               = 0x0C73,
 GL_PIXEL_MAP_I_TO_B               = 0x0C74,
 GL_PIXEL_MAP_I_TO_A               = 0x0C75,
 GL_PIXEL_MAP_R_TO_R               = 0x0C76,
 GL_PIXEL_MAP_G_TO_G               = 0x0C77,
 GL_PIXEL_MAP_B_TO_B               = 0x0C78,
 GL_PIXEL_MAP_A_TO_A               = 0x0C79,
 GL_PIXEL_MAP_I_TO_I_SIZE          = 0x0CB0,
 GL_PIXEL_MAP_S_TO_S_SIZE          = 0x0CB1,
 GL_PIXEL_MAP_I_TO_R_SIZE          = 0x0CB2,
 GL_PIXEL_MAP_I_TO_G_SIZE          = 0x0CB3,
 GL_PIXEL_MAP_I_TO_B_SIZE          = 0x0CB4,
 GL_PIXEL_MAP_I_TO_A_SIZE          = 0x0CB5,
 GL_PIXEL_MAP_R_TO_R_SIZE          = 0x0CB6,
 GL_PIXEL_MAP_G_TO_G_SIZE          = 0x0CB7,
 GL_PIXEL_MAP_B_TO_B_SIZE          = 0x0CB8,
 GL_PIXEL_MAP_A_TO_A_SIZE          = 0x0CB9,
 GL_UNPACK_SWAP_BYTES              = 0x0CF0,
 GL_UNPACK_LSB_FIRST               = 0x0CF1,
 GL_UNPACK_ROW_LENGTH              = 0x0CF2,
 GL_UNPACK_SKIP_ROWS               = 0x0CF3,
 GL_UNPACK_SKIP_PIXELS             = 0x0CF4,
 GL_UNPACK_ALIGNMENT               = 0x0CF5,
 GL_PACK_SWAP_BYTES                = 0x0D00,
 GL_PACK_LSB_FIRST                 = 0x0D01,
 GL_PACK_ROW_LENGTH                = 0x0D02,
 GL_PACK_SKIP_ROWS                 = 0x0D03,
 GL_PACK_SKIP_PIXELS               = 0x0D04,
 GL_PACK_ALIGNMENT                 = 0x0D05,
 GL_MAP_COLOR                      = 0x0D10,
 GL_MAP_STENCIL                    = 0x0D11,
 GL_INDEX_SHIFT                    = 0x0D12,
 GL_INDEX_OFFSET                   = 0x0D13,
 GL_RED_SCALE                      = 0x0D14,
 GL_RED_BIAS                       = 0x0D15,
 GL_ZOOM_X                         = 0x0D16,
 GL_ZOOM_Y                         = 0x0D17,
 GL_GREEN_SCALE                    = 0x0D18,
 GL_GREEN_BIAS                     = 0x0D19,
 GL_BLUE_SCALE                     = 0x0D1A,
 GL_BLUE_BIAS                      = 0x0D1B,
 GL_ALPHA_SCALE                    = 0x0D1C,
 GL_ALPHA_BIAS                     = 0x0D1D,
 GL_DEPTH_SCALE                    = 0x0D1E,
 GL_DEPTH_BIAS                     = 0x0D1F,
 GL_MAX_EVAL_ORDER                 = 0x0D30,
 GL_MAX_LIGHTS                     = 0x0D31,
 GL_MAX_CLIP_PLANES                = 0x0D32,
 GL_MAX_TEXTURE_SIZE               = 0x0D33,
 GL_MAX_PIXEL_MAP_TABLE            = 0x0D34,
 GL_MAX_ATTRIB_STACK_DEPTH         = 0x0D35,
 GL_MAX_MODELVIEW_STACK_DEPTH      = 0x0D36,
 GL_MAX_NAME_STACK_DEPTH           = 0x0D37,
 GL_MAX_PROJECTION_STACK_DEPTH     = 0x0D38,
 GL_MAX_TEXTURE_STACK_DEPTH        = 0x0D39,
 GL_MAX_VIEWPORT_DIMS              = 0x0D3A,
 GL_MAX_CLIENT_ATTRIB_STACK_DEPTH  = 0x0D3B,
 GL_SUBPIXEL_BITS                  = 0x0D50,
 GL_INDEX_BITS                     = 0x0D51,
 GL_RED_BITS                       = 0x0D52,
 GL_GREEN_BITS                     = 0x0D53,
 GL_BLUE_BITS                      = 0x0D54,
 GL_ALPHA_BITS                     = 0x0D55,
 GL_DEPTH_BITS                     = 0x0D56,
 GL_STENCIL_BITS                   = 0x0D57,
 GL_ACCUM_RED_BITS                 = 0x0D58,
 GL_ACCUM_GREEN_BITS               = 0x0D59,
 GL_ACCUM_BLUE_BITS                = 0x0D5A,
 GL_ACCUM_ALPHA_BITS               = 0x0D5B,
 GL_NAME_STACK_DEPTH               = 0x0D70,
 GL_AUTO_NORMAL                    = 0x0D80,
 GL_MAP1_COLOR_4                   = 0x0D90,
 GL_MAP1_INDEX                     = 0x0D91,
 GL_MAP1_NORMAL                    = 0x0D92,
 GL_MAP1_TEXTURE_COORD_1           = 0x0D93,
 GL_MAP1_TEXTURE_COORD_2           = 0x0D94,
 GL_MAP1_TEXTURE_COORD_3           = 0x0D95,
 GL_MAP1_TEXTURE_COORD_4           = 0x0D96,
 GL_MAP1_VERTEX_3                  = 0x0D97,
 GL_MAP1_VERTEX_4                  = 0x0D98,
 GL_MAP2_COLOR_4                   = 0x0DB0,
 GL_MAP2_INDEX                     = 0x0DB1,
 GL_MAP2_NORMAL                    = 0x0DB2,
 GL_MAP2_TEXTURE_COORD_1           = 0x0DB3,
 GL_MAP2_TEXTURE_COORD_2           = 0x0DB4,
 GL_MAP2_TEXTURE_COORD_3           = 0x0DB5,
 GL_MAP2_TEXTURE_COORD_4           = 0x0DB6,
 GL_MAP2_VERTEX_3                  = 0x0DB7,
 GL_MAP2_VERTEX_4                  = 0x0DB8,
 GL_MAP1_GRID_DOMAIN               = 0x0DD0,
 GL_MAP1_GRID_SEGMENTS             = 0x0DD1,
 GL_MAP2_GRID_DOMAIN               = 0x0DD2,
 GL_MAP2_GRID_SEGMENTS             = 0x0DD3,
 GL_TEXTURE_1D                     = 0x0DE0,
 GL_TEXTURE_2D                     = 0x0DE1,
 GL_FEEDBACK_BUFFER_POINTER        = 0x0DF0,
 GL_FEEDBACK_BUFFER_SIZE           = 0x0DF1,
 GL_FEEDBACK_BUFFER_TYPE           = 0x0DF2,
 GL_SELECTION_BUFFER_POINTER       = 0x0DF3,
 GL_SELECTION_BUFFER_SIZE          = 0x0DF4,
 GL_TEXTURE_WIDTH                  = 0x1000,
 GL_TEXTURE_HEIGHT                 = 0x1001,
 GL_TEXTURE_INTERNAL_FORMAT        = 0x1003,
 GL_TEXTURE_BORDER_COLOR           = 0x1004,
 GL_TEXTURE_BORDER                 = 0x1005,
 GL_DONT_CARE                      = 0x1100,
 GL_FASTEST                        = 0x1101,
 GL_NICEST                         = 0x1102,
 GL_LIGHT0                         = 0x4000,
 GL_LIGHT1                         = 0x4001,
 GL_LIGHT2                         = 0x4002,
 GL_LIGHT3                         = 0x4003,
 GL_LIGHT4                         = 0x4004,
 GL_LIGHT5                         = 0x4005,
 GL_LIGHT6                         = 0x4006,
 GL_LIGHT7                         = 0x4007,
 GL_AMBIENT                        = 0x1200,
 GL_DIFFUSE                        = 0x1201,
 GL_SPECULAR                       = 0x1202,
 GL_POSITION                       = 0x1203,
 GL_SPOT_DIRECTION                 = 0x1204,
 GL_SPOT_EXPONENT                  = 0x1205,
 GL_SPOT_CUTOFF                    = 0x1206,
 GL_CONSTANT_ATTENUATION           = 0x1207,
 GL_LINEAR_ATTENUATION             = 0x1208,
 GL_QUADRATIC_ATTENUATION          = 0x1209,
 GL_COMPILE                        = 0x1300,
 GL_COMPILE_AND_EXECUTE            = 0x1301,
 GL_CLEAR                          = 0x1500,
 GL_AND                            = 0x1501,
 GL_AND_REVERSE                    = 0x1502,
 GL_COPY                           = 0x1503,
 GL_AND_INVERTED                   = 0x1504,
 GL_NOOP                           = 0x1505,
 GL_XOR                            = 0x1506,
 GL_OR                             = 0x1507,
 GL_NOR                            = 0x1508,
 GL_EQUIV                          = 0x1509,
 GL_INVERT                         = 0x150A,
 GL_OR_REVERSE                     = 0x150B,
 GL_COPY_INVERTED                  = 0x150C,
 GL_OR_INVERTED                    = 0x150D,
 GL_NAND                           = 0x150E,
 GL_SET                            = 0x150F,
 GL_EMISSION                       = 0x1600,
 GL_SHININESS                      = 0x1601,
 GL_AMBIENT_AND_DIFFUSE            = 0x1602,
 GL_COLOR_INDEXES                  = 0x1603,
 GL_MODELVIEW                      = 0x1700,
 GL_PROJECTION                     = 0x1701,
 GL_TEXTURE                        = 0x1702,
 GL_COLOR                          = 0x1800,
 GL_DEPTH                          = 0x1801,
 GL_STENCIL                        = 0x1802,
 GL_COLOR_INDEX                    = 0x1900,
 GL_STENCIL_INDEX                  = 0x1901,
 GL_DEPTH_COMPONENT                = 0x1902,
 GL_RED                            = 0x1903,
 GL_GREEN                          = 0x1904,
 GL_BLUE                           = 0x1905,
 GL_ALPHA                          = 0x1906,
 GL_RGB                            = 0x1907,
 GL_RGBA                           = 0x1908,
 GL_LUMINANCE                      = 0x1909,
 GL_LUMINANCE_ALPHA                = 0x190A,
 GL_BITMAP                         = 0x1A00,
 GL_POINT                          = 0x1B00,
 GL_LINE                           = 0x1B01,
 GL_FILL                           = 0x1B02,
 GL_RENDER                         = 0x1C00,
 GL_FEEDBACK                       = 0x1C01,
 GL_SELECT                         = 0x1C02,
 GL_FLAT                           = 0x1D00,
 GL_SMOOTH                         = 0x1D01,
 GL_KEEP                           = 0x1E00,
 GL_REPLACE                        = 0x1E01,
 GL_INCR                           = 0x1E02,
 GL_DECR                           = 0x1E03,
 GL_VENDOR                         = 0x1F00,
 GL_RENDERER                       = 0x1F01,
 GL_VERSION                        = 0x1F02,
 GL_EXTENSIONS                     = 0x1F03,
 GL_S                              = 0x2000,
 GL_T                              = 0x2001,
 GL_R                              = 0x2002,
 GL_Q                              = 0x2003,
 GL_MODULATE                       = 0x2100,
 GL_DECAL                          = 0x2101,
 GL_TEXTURE_ENV_MODE               = 0x2200,
 GL_TEXTURE_ENV_COLOR              = 0x2201,
 GL_TEXTURE_ENV                    = 0x2300,
 GL_EYE_LINEAR                     = 0x2400,
 GL_OBJECT_LINEAR                  = 0x2401,
 GL_SPHERE_MAP                     = 0x2402,
 GL_TEXTURE_GEN_MODE               = 0x2500,
 GL_OBJECT_PLANE                   = 0x2501,
 GL_EYE_PLANE                      = 0x2502,
 GL_NEAREST                        = 0x2600,
 GL_LINEAR                         = 0x2601,
 GL_NEAREST_MIPMAP_NEAREST         = 0x2700,
 GL_LINEAR_MIPMAP_NEAREST          = 0x2701,
 GL_NEAREST_MIPMAP_LINEAR          = 0x2702,
 GL_LINEAR_MIPMAP_LINEAR           = 0x2703,
 GL_TEXTURE_MAG_FILTER             = 0x2800,
 GL_TEXTURE_MIN_FILTER             = 0x2801,
 GL_TEXTURE_WRAP_S                 = 0x2802,
 GL_TEXTURE_WRAP_T                 = 0x2803,
 GL_CLAMP                          = 0x2900,
 GL_REPEAT                         = 0x2901,
 GL_CLIENT_PIXEL_STORE_BIT         = 0x00000001,
 GL_CLIENT_VERTEX_ARRAY_BIT        = 0x00000002,
 GL_CLIENT_ALL_ATTRIB_BITS         = 0xffffffff,
 GL_POLYGON_OFFSET_FACTOR          = 0x8038,
 GL_POLYGON_OFFSET_UNITS           = 0x2A00,
 GL_POLYGON_OFFSET_POINT           = 0x2A01,
 GL_POLYGON_OFFSET_LINE            = 0x2A02,
 GL_POLYGON_OFFSET_FILL            = 0x8037,
 GL_ALPHA4                         = 0x803B,
 GL_ALPHA8                         = 0x803C,
 GL_ALPHA12                        = 0x803D,
 GL_ALPHA16                        = 0x803E,
 GL_LUMINANCE4                     = 0x803F,
 GL_LUMINANCE8                     = 0x8040,
 GL_LUMINANCE12                    = 0x8041,
 GL_LUMINANCE16                    = 0x8042,
 GL_LUMINANCE4_ALPHA4              = 0x8043,
 GL_LUMINANCE6_ALPHA2              = 0x8044,
 GL_LUMINANCE8_ALPHA8              = 0x8045,
 GL_LUMINANCE12_ALPHA4             = 0x8046,
 GL_LUMINANCE12_ALPHA12            = 0x8047,
 GL_LUMINANCE16_ALPHA16            = 0x8048,
 GL_INTENSITY                      = 0x8049,
 GL_INTENSITY4                     = 0x804A,
 GL_INTENSITY8                     = 0x804B,
 GL_INTENSITY12                    = 0x804C,
 GL_INTENSITY16                    = 0x804D,
 GL_R3_G3_B2                       = 0x2A10,
 GL_RGB4                           = 0x804F,
 GL_RGB5                           = 0x8050,
 GL_RGB8                           = 0x8051,
 GL_RGB10                          = 0x8052,
 GL_RGB12                          = 0x8053,
 GL_RGB16                          = 0x8054,
 GL_RGBA2                          = 0x8055,
 GL_RGBA4                          = 0x8056,
 GL_RGB5_A1                        = 0x8057,
 GL_RGBA8                          = 0x8058,
 GL_RGB10_A2                       = 0x8059,
 GL_RGBA12                         = 0x805A,
 GL_RGBA16                         = 0x805B,
 GL_TEXTURE_RED_SIZE               = 0x805C,
 GL_TEXTURE_GREEN_SIZE             = 0x805D,
 GL_TEXTURE_BLUE_SIZE              = 0x805E,
 GL_TEXTURE_ALPHA_SIZE             = 0x805F,
 GL_TEXTURE_LUMINANCE_SIZE         = 0x8060,
 GL_TEXTURE_INTENSITY_SIZE         = 0x8061,
 GL_PROXY_TEXTURE_1D               = 0x8063,
 GL_PROXY_TEXTURE_2D               = 0x8064,
 GL_TEXTURE_PRIORITY               = 0x8066,
 GL_TEXTURE_RESIDENT               = 0x8067,
 GL_TEXTURE_BINDING_1D             = 0x8068,
 GL_TEXTURE_BINDING_2D             = 0x8069,
 GL_TEXTURE_BINDING_3D             = 0x806A,
 GL_VERTEX_ARRAY                   = 0x8074,
 GL_NORMAL_ARRAY                   = 0x8075,
 GL_COLOR_ARRAY                    = 0x8076,
 GL_INDEX_ARRAY                    = 0x8077,
 GL_TEXTURE_COORD_ARRAY            = 0x8078,
 GL_EDGE_FLAG_ARRAY                = 0x8079,
 GL_VERTEX_ARRAY_SIZE              = 0x807A,
 GL_VERTEX_ARRAY_TYPE              = 0x807B,
 GL_VERTEX_ARRAY_STRIDE            = 0x807C,
 GL_NORMAL_ARRAY_TYPE              = 0x807E,
 GL_NORMAL_ARRAY_STRIDE            = 0x807F,
 GL_COLOR_ARRAY_SIZE               = 0x8081,
 GL_COLOR_ARRAY_TYPE               = 0x8082,
 GL_COLOR_ARRAY_STRIDE             = 0x8083,
 GL_INDEX_ARRAY_TYPE               = 0x8085,
 GL_INDEX_ARRAY_STRIDE             = 0x8086,
 GL_TEXTURE_COORD_ARRAY_SIZE       = 0x8088,
 GL_TEXTURE_COORD_ARRAY_TYPE       = 0x8089,
 GL_TEXTURE_COORD_ARRAY_STRIDE     = 0x808A,
 GL_EDGE_FLAG_ARRAY_STRIDE         = 0x808C,
 GL_VERTEX_ARRAY_POINTER           = 0x808E,
 GL_NORMAL_ARRAY_POINTER           = 0x808F,
 GL_COLOR_ARRAY_POINTER            = 0x8090,
 GL_INDEX_ARRAY_POINTER            = 0x8091,
 GL_TEXTURE_COORD_ARRAY_POINTER    = 0x8092,
 GL_EDGE_FLAG_ARRAY_POINTER        = 0x8093,
 GL_V2F                            = 0x2A20,
 GL_V3F                            = 0x2A21,
 GL_C4UB_V2F                       = 0x2A22,
 GL_C4UB_V3F                       = 0x2A23,
 GL_C3F_V3F                        = 0x2A24,
 GL_N3F_V3F                        = 0x2A25,
 GL_C4F_N3F_V3F                    = 0x2A26,
 GL_T2F_V3F                        = 0x2A27,
 GL_T4F_V4F                        = 0x2A28,
 GL_T2F_C4UB_V3F                   = 0x2A29,
 GL_T2F_C3F_V3F                    = 0x2A2A,
 GL_T2F_N3F_V3F                    = 0x2A2B,
 GL_T2F_C4F_N3F_V3F                = 0x2A2C,
 GL_T4F_C4F_N3F_V4F                = 0x2A2D,
 GL_BGR                            = 0x80E0,
 GL_BGRA                           = 0x80E1,
 GL_CONSTANT_COLOR                 = 0x8001,
 GL_ONE_MINUS_CONSTANT_COLOR       = 0x8002,
 GL_CONSTANT_ALPHA                 = 0x8003,
 GL_ONE_MINUS_CONSTANT_ALPHA       = 0x8004,
 GL_BLEND_COLOR                    = 0x8005,
 GL_FUNC_ADD                       = 0x8006,
 GL_MIN                            = 0x8007,
 GL_MAX                            = 0x8008,
 GL_BLEND_EQUATION                 = 0x8009,
 GL_BLEND_EQUATION_RGB             = 0x8009,
 GL_BLEND_EQUATION_ALPHA           = 0x883D,
 GL_FUNC_SUBTRACT                  = 0x800A,
 GL_FUNC_REVERSE_SUBTRACT          = 0x800B,
 GL_COLOR_MATRIX                   = 0x80B1,
 GL_COLOR_MATRIX_STACK_DEPTH       = 0x80B2,
 GL_MAX_COLOR_MATRIX_STACK_DEPTH   = 0x80B3,
 GL_POST_COLOR_MATRIX_RED_SCALE    = 0x80B4,
 GL_POST_COLOR_MATRIX_GREEN_SCALE  = 0x80B5,
 GL_POST_COLOR_MATRIX_BLUE_SCALE   = 0x80B6,
 GL_POST_COLOR_MATRIX_ALPHA_SCALE  = 0x80B7,
 GL_POST_COLOR_MATRIX_RED_BIAS     = 0x80B8,
 GL_POST_COLOR_MATRIX_GREEN_BIAS   = 0x80B9,
 GL_POST_COLOR_MATRIX_BLUE_BIAS    = 0x80BA,
 GL_POST_COLOR_MATRIX_ALPHA_BIAS   = 0x80BB,
 GL_COLOR_TABLE                    = 0x80D0,
 GL_POST_CONVOLUTION_COLOR_TABLE   = 0x80D1,
 GL_POST_COLOR_MATRIX_COLOR_TABLE  = 0x80D2,
 GL_PROXY_COLOR_TABLE              = 0x80D3,
 GL_PROXY_POST_CONVOLUTION_COLOR_TABLE = 0x80D4,
 GL_PROXY_POST_COLOR_MATRIX_COLOR_TABLE = 0x80D5,
 GL_COLOR_TABLE_SCALE              = 0x80D6,
 GL_COLOR_TABLE_BIAS               = 0x80D7,
 GL_COLOR_TABLE_FORMAT             = 0x80D8,
 GL_COLOR_TABLE_WIDTH              = 0x80D9,
 GL_COLOR_TABLE_RED_SIZE           = 0x80DA,
 GL_COLOR_TABLE_GREEN_SIZE         = 0x80DB,
 GL_COLOR_TABLE_BLUE_SIZE          = 0x80DC,
 GL_COLOR_TABLE_ALPHA_SIZE         = 0x80DD,
 GL_COLOR_TABLE_LUMINANCE_SIZE     = 0x80DE,
 GL_COLOR_TABLE_INTENSITY_SIZE     = 0x80DF,
 GL_CONVOLUTION_1D                 = 0x8010,
 GL_CONVOLUTION_2D                 = 0x8011,
 GL_SEPARABLE_2D                   = 0x8012,
 GL_CONVOLUTION_BORDER_MODE        = 0x8013,
 GL_CONVOLUTION_FILTER_SCALE       = 0x8014,
 GL_CONVOLUTION_FILTER_BIAS        = 0x8015,
 GL_REDUCE                         = 0x8016,
 GL_CONVOLUTION_FORMAT             = 0x8017,
 GL_CONVOLUTION_WIDTH              = 0x8018,
 GL_CONVOLUTION_HEIGHT             = 0x8019,
 GL_MAX_CONVOLUTION_WIDTH          = 0x801A,
 GL_MAX_CONVOLUTION_HEIGHT         = 0x801B,
 GL_POST_CONVOLUTION_RED_SCALE     = 0x801C,
 GL_POST_CONVOLUTION_GREEN_SCALE   = 0x801D,
 GL_POST_CONVOLUTION_BLUE_SCALE    = 0x801E,
 GL_POST_CONVOLUTION_ALPHA_SCALE   = 0x801F,
 GL_POST_CONVOLUTION_RED_BIAS      = 0x8020,
 GL_POST_CONVOLUTION_GREEN_BIAS    = 0x8021,
 GL_POST_CONVOLUTION_BLUE_BIAS     = 0x8022,
 GL_POST_CONVOLUTION_ALPHA_BIAS    = 0x8023,
 GL_CONSTANT_BORDER                = 0x8151,
 GL_REPLICATE_BORDER               = 0x8153,
 GL_CONVOLUTION_BORDER_COLOR       = 0x8154,
 GL_MAX_ELEMENTS_VERTICES          = 0x80E8,
 GL_MAX_ELEMENTS_INDICES           = 0x80E9,
 GL_HISTOGRAM                      = 0x8024,
 GL_PROXY_HISTOGRAM                = 0x8025,
 GL_HISTOGRAM_WIDTH                = 0x8026,
 GL_HISTOGRAM_FORMAT               = 0x8027,
 GL_HISTOGRAM_RED_SIZE             = 0x8028,
 GL_HISTOGRAM_GREEN_SIZE           = 0x8029,
 GL_HISTOGRAM_BLUE_SIZE            = 0x802A,
 GL_HISTOGRAM_ALPHA_SIZE           = 0x802B,
 GL_HISTOGRAM_LUMINANCE_SIZE       = 0x802C,
 GL_HISTOGRAM_SINK                 = 0x802D,
 GL_MINMAX                         = 0x802E,
 GL_MINMAX_FORMAT                  = 0x802F,
 GL_MINMAX_SINK                    = 0x8030,
 GL_TABLE_TOO_LARGE                = 0x8031,
 GL_UNSIGNED_BYTE_3_3_2            = 0x8032,
 GL_UNSIGNED_SHORT_4_4_4_4         = 0x8033,
 GL_UNSIGNED_SHORT_5_5_5_1         = 0x8034,
 GL_UNSIGNED_INT_8_8_8_8           = 0x8035,
 GL_UNSIGNED_INT_10_10_10_2        = 0x8036,
 GL_UNSIGNED_BYTE_2_3_3_REV        = 0x8362,
 GL_UNSIGNED_SHORT_5_6_5           = 0x8363,
 GL_UNSIGNED_SHORT_5_6_5_REV       = 0x8364,
 GL_UNSIGNED_SHORT_4_4_4_4_REV     = 0x8365,
 GL_UNSIGNED_SHORT_1_5_5_5_REV     = 0x8366,
 GL_UNSIGNED_INT_8_8_8_8_REV       = 0x8367,
 GL_UNSIGNED_INT_2_10_10_10_REV    = 0x8368,
 GL_RESCALE_NORMAL                 = 0x803A,
 GL_LIGHT_MODEL_COLOR_CONTROL      = 0x81F8,
 GL_SINGLE_COLOR                   = 0x81F9,
 GL_SEPARATE_SPECULAR_COLOR        = 0x81FA,
 GL_PACK_SKIP_IMAGES               = 0x806B,
 GL_PACK_IMAGE_HEIGHT              = 0x806C,
 GL_UNPACK_SKIP_IMAGES             = 0x806D,
 GL_UNPACK_IMAGE_HEIGHT            = 0x806E,
 GL_TEXTURE_3D                     = 0x806F,
 GL_PROXY_TEXTURE_3D               = 0x8070,
 GL_TEXTURE_DEPTH                  = 0x8071,
 GL_TEXTURE_WRAP_R                 = 0x8072,
 GL_MAX_3D_TEXTURE_SIZE            = 0x8073,
 GL_CLAMP_TO_EDGE                  = 0x812F,
 GL_CLAMP_TO_BORDER                = 0x812D,
 GL_TEXTURE_MIN_LOD                = 0x813A,
 GL_TEXTURE_MAX_LOD                = 0x813B,
 GL_TEXTURE_BASE_LEVEL             = 0x813C,
 GL_TEXTURE_MAX_LEVEL              = 0x813D,
 GL_SMOOTH_POINT_SIZE_RANGE        = 0x0B12,
 GL_SMOOTH_POINT_SIZE_GRANULARITY  = 0x0B13,
 GL_SMOOTH_LINE_WIDTH_RANGE        = 0x0B22,
 GL_SMOOTH_LINE_WIDTH_GRANULARITY  = 0x0B23,
 GL_ALIASED_POINT_SIZE_RANGE       = 0x846D,
 GL_ALIASED_LINE_WIDTH_RANGE       = 0x846E,
 GL_TEXTURE0                       = 0x84C0,
 GL_TEXTURE1                       = 0x84C1,
 GL_TEXTURE2                       = 0x84C2,
 GL_TEXTURE3                       = 0x84C3,
 GL_TEXTURE4                       = 0x84C4,
 GL_TEXTURE5                       = 0x84C5,
 GL_TEXTURE6                       = 0x84C6,
 GL_TEXTURE7                       = 0x84C7,
 GL_TEXTURE8                       = 0x84C8,
 GL_TEXTURE9                       = 0x84C9,
 GL_TEXTURE10                      = 0x84CA,
 GL_TEXTURE11                      = 0x84CB,
 GL_TEXTURE12                      = 0x84CC,
 GL_TEXTURE13                      = 0x84CD,
 GL_TEXTURE14                      = 0x84CE,
 GL_TEXTURE15                      = 0x84CF,
 GL_TEXTURE16                      = 0x84D0,
 GL_TEXTURE17                      = 0x84D1,
 GL_TEXTURE18                      = 0x84D2,
 GL_TEXTURE19                      = 0x84D3,
 GL_TEXTURE20                      = 0x84D4,
 GL_TEXTURE21                      = 0x84D5,
 GL_TEXTURE22                      = 0x84D6,
 GL_TEXTURE23                      = 0x84D7,
 GL_TEXTURE24                      = 0x84D8,
 GL_TEXTURE25                      = 0x84D9,
 GL_TEXTURE26                      = 0x84DA,
 GL_TEXTURE27                      = 0x84DB,
 GL_TEXTURE28                      = 0x84DC,
 GL_TEXTURE29                      = 0x84DD,
 GL_TEXTURE30                      = 0x84DE,
 GL_TEXTURE31                      = 0x84DF,
 GL_ACTIVE_TEXTURE                 = 0x84E0,
 GL_CLIENT_ACTIVE_TEXTURE          = 0x84E1,
 GL_MAX_TEXTURE_UNITS              = 0x84E2,
 GL_COMBINE                        = 0x8570,
 GL_COMBINE_RGB                    = 0x8571,
 GL_COMBINE_ALPHA                  = 0x8572,
 GL_RGB_SCALE                      = 0x8573,
 GL_ADD_SIGNED                     = 0x8574,
 GL_INTERPOLATE                    = 0x8575,
 GL_CONSTANT                       = 0x8576,
 GL_PRIMARY_COLOR                  = 0x8577,
 GL_PREVIOUS                       = 0x8578,
 GL_SUBTRACT                       = 0x84E7,
 GL_SRC0_RGB                       = 0x8580,
 GL_SRC1_RGB                       = 0x8581,
 GL_SRC2_RGB                       = 0x8582,
 GL_SRC3_RGB                       = 0x8583,
 GL_SRC4_RGB                       = 0x8584,
 GL_SRC5_RGB                       = 0x8585,
 GL_SRC6_RGB                       = 0x8586,
 GL_SRC7_RGB                       = 0x8587,
 GL_SRC0_ALPHA                     = 0x8588,
 GL_SRC1_ALPHA                     = 0x8589,
 GL_SRC2_ALPHA                     = 0x858A,
 GL_SRC3_ALPHA                     = 0x858B,
 GL_SRC4_ALPHA                     = 0x858C,
 GL_SRC5_ALPHA                     = 0x858D,
 GL_SRC6_ALPHA                     = 0x858E,
 GL_SRC7_ALPHA                     = 0x858F,
 GL_SOURCE0_RGB                    = 0x8580,
 GL_SOURCE1_RGB                    = 0x8581,
 GL_SOURCE2_RGB                    = 0x8582,
 GL_SOURCE3_RGB                    = 0x8583,
 GL_SOURCE4_RGB                    = 0x8584,
 GL_SOURCE5_RGB                    = 0x8585,
 GL_SOURCE6_RGB                    = 0x8586,
 GL_SOURCE7_RGB                    = 0x8587,
 GL_SOURCE0_ALPHA                  = 0x8588,
 GL_SOURCE1_ALPHA                  = 0x8589,
 GL_SOURCE2_ALPHA                  = 0x858A,
 GL_SOURCE3_ALPHA                  = 0x858B,
 GL_SOURCE4_ALPHA                  = 0x858C,
 GL_SOURCE5_ALPHA                  = 0x858D,
 GL_SOURCE6_ALPHA                  = 0x858E,
 GL_SOURCE7_ALPHA                  = 0x858F,
 GL_OPERAND0_RGB                   = 0x8590,
 GL_OPERAND1_RGB                   = 0x8591,
 GL_OPERAND2_RGB                   = 0x8592,
 GL_OPERAND3_RGB                   = 0x8593,
 GL_OPERAND4_RGB                   = 0x8594,
 GL_OPERAND5_RGB                   = 0x8595,
 GL_OPERAND6_RGB                   = 0x8596,
 GL_OPERAND7_RGB                   = 0x8597,
 GL_OPERAND0_ALPHA                 = 0x8598,
 GL_OPERAND1_ALPHA                 = 0x8599,
 GL_OPERAND2_ALPHA                 = 0x859A,
 GL_OPERAND3_ALPHA                 = 0x859B,
 GL_OPERAND4_ALPHA                 = 0x859C,
 GL_OPERAND5_ALPHA                 = 0x859D,
 GL_OPERAND6_ALPHA                 = 0x859E,
 GL_OPERAND7_ALPHA                 = 0x859F,
 GL_DOT3_RGB                       = 0x86AE,
 GL_DOT3_RGBA                      = 0x86AF,
 GL_TRANSPOSE_MODELVIEW_MATRIX     = 0x84E3,
 GL_TRANSPOSE_PROJECTION_MATRIX    = 0x84E4,
 GL_TRANSPOSE_TEXTURE_MATRIX       = 0x84E5,
 GL_TRANSPOSE_COLOR_MATRIX         = 0x84E6,
 GL_NORMAL_MAP                     = 0x8511,
 GL_REFLECTION_MAP                 = 0x8512,
 GL_TEXTURE_CUBE_MAP               = 0x8513,
 GL_TEXTURE_BINDING_CUBE_MAP       = 0x8514,
 GL_TEXTURE_CUBE_MAP_POSITIVE_X    = 0x8515,
 GL_TEXTURE_CUBE_MAP_NEGATIVE_X    = 0x8516,
 GL_TEXTURE_CUBE_MAP_POSITIVE_Y    = 0x8517,
 GL_TEXTURE_CUBE_MAP_NEGATIVE_Y    = 0x8518,
 GL_TEXTURE_CUBE_MAP_POSITIVE_Z    = 0x8519,
 GL_TEXTURE_CUBE_MAP_NEGATIVE_Z    = 0x851A,
 GL_PROXY_TEXTURE_CUBE_MAP         = 0x851B,
 GL_MAX_CUBE_MAP_TEXTURE_SIZE      = 0x851C,
 GL_COMPRESSED_ALPHA               = 0x84E9,
 GL_COMPRESSED_LUMINANCE           = 0x84EA,
 GL_COMPRESSED_LUMINANCE_ALPHA     = 0x84EB,
 GL_COMPRESSED_INTENSITY           = 0x84EC,
 GL_COMPRESSED_RGB                 = 0x84ED,
 GL_COMPRESSED_RGBA                = 0x84EE,
 GL_TEXTURE_COMPRESSION_HINT       = 0x84EF,
 GL_TEXTURE_COMPRESSED_IMAGE_SIZE  = 0x86A0,
 GL_TEXTURE_COMPRESSED             = 0x86A1,
 GL_NUM_COMPRESSED_TEXTURE_FORMATS = 0x86A2,
 GL_COMPRESSED_TEXTURE_FORMATS     = 0x86A3,
 GL_MULTISAMPLE                    = 0x809D,
 GL_SAMPLE_ALPHA_TO_COVERAGE       = 0x809E,
 GL_SAMPLE_ALPHA_TO_ONE            = 0x809F,
 GL_SAMPLE_COVERAGE                = 0x80A0,
 GL_SAMPLE_BUFFERS                 = 0x80A8,
 GL_SAMPLES                        = 0x80A9,
 GL_SAMPLE_COVERAGE_VALUE          = 0x80AA,
 GL_SAMPLE_COVERAGE_INVERT         = 0x80AB,
 GL_MULTISAMPLE_BIT                = 0x20000000,
 GL_DEPTH_COMPONENT16              = 0x81A5,
 GL_DEPTH_COMPONENT24              = 0x81A6,
 GL_DEPTH_COMPONENT32              = 0x81A7,
 GL_TEXTURE_DEPTH_SIZE             = 0x884A,
 GL_DEPTH_TEXTURE_MODE             = 0x884B,
 GL_TEXTURE_COMPARE_MODE           = 0x884C,
 GL_TEXTURE_COMPARE_FUNC           = 0x884D,
 GL_COMPARE_R_TO_TEXTURE           = 0x884E,
 GL_QUERY_COUNTER_BITS             = 0x8864,
 GL_CURRENT_QUERY                  = 0x8865,
 GL_QUERY_RESULT                   = 0x8866,
 GL_QUERY_RESULT_AVAILABLE         = 0x8867,
 GL_SAMPLES_PASSED                 = 0x8914,
 GL_FOG_COORD_SRC                  = 0x8450,
 GL_FOG_COORD                      = 0x8451,
 GL_FRAGMENT_DEPTH                 = 0x8452,
 GL_CURRENT_FOG_COORD              = 0x8453  ,
 GL_FOG_COORD_ARRAY_TYPE           = 0x8454,
 GL_FOG_COORD_ARRAY_STRIDE         = 0x8455,
 GL_FOG_COORD_ARRAY_POINTER        = 0x8456,
 GL_FOG_COORD_ARRAY                = 0x8457,
 GL_FOG_COORDINATE_SOURCE          = 0x8450,
 GL_FOG_COORDINATE                 = 0x8451,
 GL_CURRENT_FOG_COORDINATE         = 0x8453  ,
 GL_FOG_COORDINATE_ARRAY_TYPE      = 0x8454,
 GL_FOG_COORDINATE_ARRAY_STRIDE    = 0x8455,
 GL_FOG_COORDINATE_ARRAY_POINTER   = 0x8456,
 GL_FOG_COORDINATE_ARRAY           = 0x8457,
 GL_COLOR_SUM                      = 0x8458,
 GL_CURRENT_SECONDARY_COLOR        = 0x8459,
 GL_SECONDARY_COLOR_ARRAY_SIZE     = 0x845A,
 GL_SECONDARY_COLOR_ARRAY_TYPE     = 0x845B,
 GL_SECONDARY_COLOR_ARRAY_STRIDE   = 0x845C,
 GL_SECONDARY_COLOR_ARRAY_POINTER  = 0x845D,
 GL_SECONDARY_COLOR_ARRAY          = 0x845E,
 GL_POINT_SIZE_MIN                 = 0x8126,
 GL_POINT_SIZE_MAX                 = 0x8127,
 GL_POINT_FADE_THRESHOLD_SIZE      = 0x8128,
 GL_POINT_DISTANCE_ATTENUATION     = 0x8129,
 GL_BLEND_DST_RGB                  = 0x80C8,
 GL_BLEND_SRC_RGB                  = 0x80C9,
 GL_BLEND_DST_ALPHA                = 0x80CA,
 GL_BLEND_SRC_ALPHA                = 0x80CB,
 GL_GENERATE_MIPMAP                = 0x8191,
 GL_GENERATE_MIPMAP_HINT           = 0x8192,
 GL_INCR_WRAP                      = 0x8507,
 GL_DECR_WRAP                      = 0x8508,
 GL_MIRRORED_REPEAT                = 0x8370,
 GL_MAX_TEXTURE_LOD_BIAS           = 0x84FD,
 GL_TEXTURE_FILTER_CONTROL         = 0x8500,
 GL_TEXTURE_LOD_BIAS               = 0x8501,
 GL_ARRAY_BUFFER                                = 0x8892,
 GL_ELEMENT_ARRAY_BUFFER                        = 0x8893,
 GL_ARRAY_BUFFER_BINDING                        = 0x8894,
 GL_ELEMENT_ARRAY_BUFFER_BINDING                = 0x8895,
 GL_VERTEX_ARRAY_BUFFER_BINDING                 = 0x8896,
 GL_NORMAL_ARRAY_BUFFER_BINDING                 = 0x8897,
 GL_COLOR_ARRAY_BUFFER_BINDING                  = 0x8898,
 GL_INDEX_ARRAY_BUFFER_BINDING                  = 0x8899,
 GL_TEXTURE_COORD_ARRAY_BUFFER_BINDING          = 0x889A,
 GL_EDGE_FLAG_ARRAY_BUFFER_BINDING              = 0x889B,
 GL_SECONDARY_COLOR_ARRAY_BUFFER_BINDING        = 0x889C,
 GL_FOG_COORD_ARRAY_BUFFER_BINDING              = 0x889D,
 GL_WEIGHT_ARRAY_BUFFER_BINDING                 = 0x889E,
 GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING          = 0x889F,
 GL_STREAM_DRAW                                 = 0x88E0,
 GL_STREAM_READ                                 = 0x88E1,
 GL_STREAM_COPY                                 = 0x88E2,
 GL_STATIC_DRAW                                 = 0x88E4,
 GL_STATIC_READ                                 = 0x88E5,
 GL_STATIC_COPY                                 = 0x88E6,
 GL_DYNAMIC_DRAW                                = 0x88E8,
 GL_DYNAMIC_READ                                = 0x88E9,
 GL_DYNAMIC_COPY                                = 0x88EA,
 GL_READ_ONLY                                   = 0x88B8,
 GL_WRITE_ONLY                                  = 0x88B9,
 GL_READ_WRITE                                  = 0x88BA,
 GL_BUFFER_SIZE                                 = 0x8764,
 GL_BUFFER_USAGE                                = 0x8765,
 GL_BUFFER_ACCESS                               = 0x88BB,
 GL_BUFFER_MAPPED                               = 0x88BC,
 GL_BUFFER_MAP_POINTER                          = 0x88BD,
 GL_FOG_COORDINATE_ARRAY_BUFFER_BINDING         = 0x889D,
 GL_CURRENT_PROGRAM                = 0x8B8D,
 GL_SHADER_TYPE                    = 0x8B4F,
 GL_DELETE_STATUS                  = 0x8B80,
 GL_COMPILE_STATUS                 = 0x8B81,
 GL_LINK_STATUS                    = 0x8B82,
 GL_VALIDATE_STATUS                = 0x8B83,
 GL_INFO_LOG_LENGTH                = 0x8B84,
 GL_ATTACHED_SHADERS               = 0x8B85,
 GL_ACTIVE_UNIFORMS                = 0x8B86,
 GL_ACTIVE_UNIFORM_MAX_LENGTH      = 0x8B87,
 GL_SHADER_SOURCE_LENGTH           = 0x8B88,
 GL_FLOAT_VEC2                     = 0x8B50,
 GL_FLOAT_VEC3                     = 0x8B51,
 GL_FLOAT_VEC4                     = 0x8B52,
 GL_INT_VEC2                       = 0x8B53,
 GL_INT_VEC3                       = 0x8B54,
 GL_INT_VEC4                       = 0x8B55,
 GL_BOOL                           = 0x8B56,
 GL_BOOL_VEC2                      = 0x8B57,
 GL_BOOL_VEC3                      = 0x8B58,
 GL_BOOL_VEC4                      = 0x8B59,
 GL_FLOAT_MAT2                     = 0x8B5A,
 GL_FLOAT_MAT3                     = 0x8B5B,
 GL_FLOAT_MAT4                     = 0x8B5C,
 GL_SAMPLER_1D                     = 0x8B5D,
 GL_SAMPLER_2D                     = 0x8B5E,
 GL_SAMPLER_3D                     = 0x8B5F,
 GL_SAMPLER_CUBE                   = 0x8B60,
 GL_SAMPLER_1D_SHADOW              = 0x8B61,
 GL_SAMPLER_2D_SHADOW              = 0x8B62,
 GL_SHADING_LANGUAGE_VERSION       = 0x8B8C,
 GL_VERTEX_SHADER                  = 0x8B31,
 GL_MAX_VERTEX_UNIFORM_COMPONENTS  = 0x8B4A,
 GL_MAX_VARYING_FLOATS             = 0x8B4B,
 GL_MAX_VERTEX_TEXTURE_IMAGE_UNITS = 0x8B4C,
 GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS = 0x8B4D,
 GL_ACTIVE_ATTRIBUTES              = 0x8B89,
 GL_ACTIVE_ATTRIBUTE_MAX_LENGTH    = 0x8B8A,
 GL_FRAGMENT_SHADER                = 0x8B30,
 GL_MAX_FRAGMENT_UNIFORM_COMPONENTS = 0x8B49,
 GL_FRAGMENT_SHADER_DERIVATIVE_HINT = 0x8B8B,
 GL_MAX_VERTEX_ATTRIBS             = 0x8869,
 GL_VERTEX_ATTRIB_ARRAY_ENABLED    = 0x8622,
 GL_VERTEX_ATTRIB_ARRAY_SIZE       = 0x8623,
 GL_VERTEX_ATTRIB_ARRAY_STRIDE     = 0x8624,
 GL_VERTEX_ATTRIB_ARRAY_TYPE       = 0x8625,
 GL_VERTEX_ATTRIB_ARRAY_NORMALIZED = 0x886A,
 GL_CURRENT_VERTEX_ATTRIB          = 0x8626,
 GL_VERTEX_ATTRIB_ARRAY_POINTER    = 0x8645,
 GL_VERTEX_PROGRAM_POINT_SIZE      = 0x8642,
 GL_VERTEX_PROGRAM_TWO_SIDE        = 0x8643,
 GL_MAX_TEXTURE_COORDS             = 0x8871,
 GL_MAX_TEXTURE_IMAGE_UNITS        = 0x8872,
 GL_MAX_DRAW_BUFFERS               = 0x8824,
 GL_DRAW_BUFFER0                   = 0x8825,
 GL_DRAW_BUFFER1                   = 0x8826,
 GL_DRAW_BUFFER2                   = 0x8827,
 GL_DRAW_BUFFER3                   = 0x8828,
 GL_DRAW_BUFFER4                   = 0x8829,
 GL_DRAW_BUFFER5                   = 0x882A,
 GL_DRAW_BUFFER6                   = 0x882B,
 GL_DRAW_BUFFER7                   = 0x882C,
 GL_DRAW_BUFFER8                   = 0x882D,
 GL_DRAW_BUFFER9                   = 0x882E,
 GL_DRAW_BUFFER10                  = 0x882F,
 GL_DRAW_BUFFER11                  = 0x8830,
 GL_DRAW_BUFFER12                  = 0x8831,
 GL_DRAW_BUFFER13                  = 0x8832,
 GL_DRAW_BUFFER14                  = 0x8833,
 GL_DRAW_BUFFER15                  = 0x8834,
 GL_POINT_SPRITE                   = 0x8861,
 GL_COORD_REPLACE                  = 0x8862,
 GL_POINT_SPRITE_COORD_ORIGIN      = 0x8CA0,
 GL_LOWER_LEFT                     = 0x8CA1,
 GL_UPPER_LEFT                     = 0x8CA2,
 GL_STENCIL_BACK_FUNC              = 0x8800,
 GL_STENCIL_BACK_VALUE_MASK        = 0x8CA4,
 GL_STENCIL_BACK_REF               = 0x8CA3,
 GL_STENCIL_BACK_FAIL              = 0x8801,
 GL_STENCIL_BACK_PASS_DEPTH_FAIL   = 0x8802,
 GL_STENCIL_BACK_PASS_DEPTH_PASS   = 0x8803,
 GL_STENCIL_BACK_WRITEMASK         = 0x8CA5,
 GL_CURRENT_RASTER_SECONDARY_COLOR = 0x845F,
 GL_PIXEL_PACK_BUFFER              = 0x88EB,
 GL_PIXEL_UNPACK_BUFFER            = 0x88EC,
 GL_PIXEL_PACK_BUFFER_BINDING      = 0x88ED,
 GL_PIXEL_UNPACK_BUFFER_BINDING    = 0x88EF,
 GL_FLOAT_MAT2x3                   = 0x8B65,
 GL_FLOAT_MAT2x4                   = 0x8B66,
 GL_FLOAT_MAT3x2                   = 0x8B67,
 GL_FLOAT_MAT3x4                   = 0x8B68,
 GL_FLOAT_MAT4x2                   = 0x8B69,
 GL_FLOAT_MAT4x3                   = 0x8B6A,
 GL_SRGB                           = 0x8C40,
 GL_SRGB8                          = 0x8C41,
 GL_SRGB_ALPHA                     = 0x8C42,
 GL_SRGB8_ALPHA8                   = 0x8C43,
 GL_SLUMINANCE_ALPHA               = 0x8C44,
 GL_SLUMINANCE8_ALPHA8             = 0x8C45,
 GL_SLUMINANCE                     = 0x8C46,
 GL_SLUMINANCE8                    = 0x8C47,
 GL_COMPRESSED_SRGB                = 0x8C48,
 GL_COMPRESSED_SRGB_ALPHA          = 0x8C49,
 GL_COMPRESSED_SLUMINANCE          = 0x8C4A,
 GL_COMPRESSED_SLUMINANCE_ALPHA    = 0x8C4B,
};
typedef unsigned int GLenum;
typedef unsigned char GLboolean;
typedef unsigned int GLbitfield;
typedef signed char GLbyte;
typedef short GLshort;
typedef int GLint;
typedef int GLsizei;
typedef unsigned char GLubyte;
typedef unsigned short GLushort;
typedef unsigned int GLuint;
typedef float GLfloat;
typedef float GLclampf;
typedef double GLdouble;
typedef double GLclampd;
typedef void GLvoid;
typedef long GLintptr;
typedef long GLsizeiptr;
typedef char GLchar;
typedef char GLcharARB;
typedef void *GLhandleARB;
typedef long GLintptrARB;
typedef long GLsizeiptrARB;
typedef unsigned short GLhalfARB;
typedef unsigned short GLhalf;
void glActiveTextureARB (GLenum);
void glClientActiveTextureARB (GLenum);
void glMultiTexCoord1dARB (GLenum, GLdouble);
void glMultiTexCoord1dvARB (GLenum, const GLdouble *);
void glMultiTexCoord1fARB (GLenum, GLfloat);
void glMultiTexCoord1fvARB (GLenum, const GLfloat *);
void glMultiTexCoord1iARB (GLenum, GLint);
void glMultiTexCoord1ivARB (GLenum, const GLint *);
void glMultiTexCoord1sARB (GLenum, GLshort);
void glMultiTexCoord1svARB (GLenum, const GLshort *);
void glMultiTexCoord2dARB (GLenum, GLdouble, GLdouble);
void glMultiTexCoord2dvARB (GLenum, const GLdouble *);
void glMultiTexCoord2fARB (GLenum, GLfloat, GLfloat);
void glMultiTexCoord2fvARB (GLenum, const GLfloat *);
void glMultiTexCoord2iARB (GLenum, GLint, GLint);
void glMultiTexCoord2ivARB (GLenum, const GLint *);
void glMultiTexCoord2sARB (GLenum, GLshort, GLshort);
void glMultiTexCoord2svARB (GLenum, const GLshort *);
void glMultiTexCoord3dARB (GLenum, GLdouble, GLdouble, GLdouble);
void glMultiTexCoord3dvARB (GLenum, const GLdouble *);
void glMultiTexCoord3fARB (GLenum, GLfloat, GLfloat, GLfloat);
void glMultiTexCoord3fvARB (GLenum, const GLfloat *);
void glMultiTexCoord3iARB (GLenum, GLint, GLint, GLint);
void glMultiTexCoord3ivARB (GLenum, const GLint *);
void glMultiTexCoord3sARB (GLenum, GLshort, GLshort, GLshort);
void glMultiTexCoord3svARB (GLenum, const GLshort *);
void glMultiTexCoord4dARB (GLenum, GLdouble, GLdouble, GLdouble, GLdouble);
void glMultiTexCoord4dvARB (GLenum, const GLdouble *);
void glMultiTexCoord4fARB (GLenum, GLfloat, GLfloat, GLfloat, GLfloat);
void glMultiTexCoord4fvARB (GLenum, const GLfloat *);
void glMultiTexCoord4iARB (GLenum, GLint, GLint, GLint, GLint);
void glMultiTexCoord4ivARB (GLenum, const GLint *);
void glMultiTexCoord4sARB (GLenum, GLshort, GLshort, GLshort, GLshort);
void glMultiTexCoord4svARB (GLenum, const GLshort *);
void glLoadTransposeMatrixfARB (const GLfloat *);
void glLoadTransposeMatrixdARB (const GLdouble *);
void glMultTransposeMatrixfARB (const GLfloat *);
void glMultTransposeMatrixdARB (const GLdouble *);
void glSampleCoverageARB (GLclampf, GLboolean);
void glSamplePassARB (GLenum);
void glCompressedTexImage3DARB (GLenum, GLint, GLenum, GLsizei, GLsizei, GLsizei, GLint, GLsizei, const GLvoid *);
void glCompressedTexImage2DARB (GLenum, GLint, GLenum, GLsizei, GLsizei, GLint, GLsizei, const GLvoid *);
void glCompressedTexImage1DARB (GLenum, GLint, GLenum, GLsizei, GLint, GLsizei, const GLvoid *);
void glCompressedTexSubImage3DARB (GLenum, GLint, GLint, GLint, GLint, GLsizei, GLsizei, GLsizei, GLenum, GLsizei, const GLvoid *);
void glCompressedTexSubImage2DARB (GLenum, GLint, GLint, GLint, GLsizei, GLsizei, GLenum, GLsizei, const GLvoid *);
void glCompressedTexSubImage1DARB (GLenum, GLint, GLint, GLsizei, GLenum, GLsizei, const GLvoid *);
void glGetCompressedTexImageARB (GLenum, GLint, GLvoid *);
void glWeightbvARB(GLint, const GLbyte *);
void glWeightsvARB(GLint, const GLshort *);
void glWeightivARB(GLint, const GLint *);
void glWeightfvARB(GLint, const GLfloat *);
void glWeightdvARB(GLint, const GLdouble *);
void glWeightubvARB(GLint, const GLubyte *);
void glWeightusvARB(GLint, const GLushort *);
void glWeightuivARB(GLint, const GLuint *);
void glWeightPointerARB(GLint, GLenum, GLsizei, const GLvoid *);
void glVertexBlendARB(GLint);
void glWindowPos2dARB (GLdouble, GLdouble);
void glWindowPos2dvARB (const GLdouble *);
void glWindowPos2fARB (GLfloat, GLfloat);
void glWindowPos2fvARB (const GLfloat *);
void glWindowPos2iARB (GLint, GLint);
void glWindowPos2ivARB (const GLint *);
void glWindowPos2sARB (GLshort, GLshort);
void glWindowPos2svARB (const GLshort *);
void glWindowPos3dARB (GLdouble, GLdouble, GLdouble);
void glWindowPos3dvARB (const GLdouble *);
void glWindowPos3fARB (GLfloat, GLfloat, GLfloat);
void glWindowPos3fvARB (const GLfloat *);
void glWindowPos3iARB (GLint, GLint, GLint);
void glWindowPos3ivARB (const GLint *);
void glWindowPos3sARB (GLshort, GLshort, GLshort);
void glWindowPos3svARB (const GLshort *);
void glGenQueriesARB(GLsizei n, GLuint *ids);
void glDeleteQueriesARB(GLsizei n, const GLuint *ids);
GLboolean glIsQueryARB(GLuint id);
void glBeginQueryARB(GLenum target, GLuint id);
void glEndQueryARB(GLenum target);
void glGetQueryivARB(GLenum target, GLenum pname, GLint *params);
void glGetQueryObjectivARB(GLuint id, GLenum pname, GLint *params);
void glGetQueryObjectuivARB(GLuint id, GLenum pname, GLuint *params);
void glPointParameterfARB(GLenum pname, GLfloat param);
void glPointParameterfvARB(GLenum pname, const GLfloat *params);
void glBindProgramARB(GLenum target, GLuint program);
void glDeleteProgramsARB(GLsizei n, const GLuint *programs);
void glGenProgramsARB(GLsizei n, GLuint *programs);
GLboolean glIsProgramARB(GLuint program);
void glProgramEnvParameter4dARB(GLenum target, GLuint index, GLdouble x, GLdouble y, GLdouble z, GLdouble w);
void glProgramEnvParameter4dvARB(GLenum target, GLuint index, const GLdouble *params);
void glProgramEnvParameter4fARB(GLenum target, GLuint index, GLfloat x, GLfloat y, GLfloat z, GLfloat w);
void glProgramEnvParameter4fvARB(GLenum target, GLuint index, const GLfloat *params);
void glProgramLocalParameter4dARB(GLenum target, GLuint index, GLdouble x, GLdouble y, GLdouble z, GLdouble w);
void glProgramLocalParameter4dvARB(GLenum target, GLuint index, const GLdouble *params);
void glProgramLocalParameter4fARB(GLenum target, GLuint index, GLfloat x, GLfloat y, GLfloat z, GLfloat w);
void glProgramLocalParameter4fvARB(GLenum target, GLuint index, const GLfloat *params);
void glGetProgramEnvParameterdvARB(GLenum target, GLuint index, GLdouble *params);
void glGetProgramEnvParameterfvARB(GLenum target, GLuint index, GLfloat *params);
void glProgramEnvParameters4fvEXT(GLenum target, GLuint index, GLsizei count, const GLfloat *params);
void glProgramLocalParameters4fvEXT(GLenum target, GLuint index, GLsizei count, const GLfloat *params);
void glGetProgramLocalParameterdvARB(GLenum target, GLuint index, GLdouble *params);
void glGetProgramLocalParameterfvARB(GLenum target, GLuint index, GLfloat *params);
void glProgramStringARB(GLenum target, GLenum format, GLsizei len, const GLvoid *string);
void glGetProgramStringARB(GLenum target, GLenum pname, GLvoid *string);
void glGetProgramivARB(GLenum target, GLenum pname, GLint *params);
void glVertexAttrib1dARB(GLuint index, GLdouble x);
void glVertexAttrib1dvARB(GLuint index, const GLdouble *v);
void glVertexAttrib1fARB(GLuint index, GLfloat x);
void glVertexAttrib1fvARB(GLuint index, const GLfloat *v);
void glVertexAttrib1sARB(GLuint index, GLshort x);
void glVertexAttrib1svARB(GLuint index, const GLshort *v);
void glVertexAttrib2dARB(GLuint index, GLdouble x, GLdouble y);
void glVertexAttrib2dvARB(GLuint index, const GLdouble *v);
void glVertexAttrib2fARB(GLuint index, GLfloat x, GLfloat y);
void glVertexAttrib2fvARB(GLuint index, const GLfloat *v);
void glVertexAttrib2sARB(GLuint index, GLshort x, GLshort y);
void glVertexAttrib2svARB(GLuint index, const GLshort *v);
void glVertexAttrib3dARB(GLuint index, GLdouble x, GLdouble y, GLdouble z);
void glVertexAttrib3dvARB(GLuint index, const GLdouble *v);
void glVertexAttrib3fARB(GLuint index, GLfloat x, GLfloat y, GLfloat z);
void glVertexAttrib3fvARB(GLuint index, const GLfloat *v);
void glVertexAttrib3sARB(GLuint index, GLshort x, GLshort y, GLshort z);
void glVertexAttrib3svARB(GLuint index, const GLshort *v);
void glVertexAttrib4NbvARB(GLuint index, const GLbyte *v);
void glVertexAttrib4NivARB(GLuint index, const GLint *v);
void glVertexAttrib4NsvARB(GLuint index, const GLshort *v);
void glVertexAttrib4NubARB(GLuint index, GLubyte x, GLubyte y, GLubyte z, GLubyte w);
void glVertexAttrib4NubvARB(GLuint index, const GLubyte *v);
void glVertexAttrib4NuivARB(GLuint index, const GLuint *v);
void glVertexAttrib4NusvARB(GLuint index, const GLushort *v);
void glVertexAttrib4bvARB(GLuint index, const GLbyte *v);
void glVertexAttrib4dARB(GLuint index, GLdouble x, GLdouble y, GLdouble z, GLdouble w);
void glVertexAttrib4dvARB(GLuint index, const GLdouble *v);
void glVertexAttrib4fARB(GLuint index, GLfloat x, GLfloat y, GLfloat z, GLfloat w);
void glVertexAttrib4fvARB(GLuint index, const GLfloat *v);
void glVertexAttrib4ivARB(GLuint index, const GLint *v);
void glVertexAttrib4sARB(GLuint index, GLshort x, GLshort y, GLshort z, GLshort w);
void glVertexAttrib4svARB(GLuint index, const GLshort *v);
void glVertexAttrib4ubvARB(GLuint index, const GLubyte *v);
void glVertexAttrib4uivARB(GLuint index, const GLuint *v);
void glVertexAttrib4usvARB(GLuint index, const GLushort *v);
void glVertexAttribPointerARB(GLuint index, GLint size, GLenum type, GLboolean normalized, GLsizei stride, const GLvoid *pointer);
void glDisableVertexAttribArrayARB(GLuint index);
void glEnableVertexAttribArrayARB(GLuint index);
void glGetVertexAttribPointervARB(GLuint index, GLenum pname, GLvoid **pointer);
void glGetVertexAttribdvARB(GLuint index, GLenum pname, GLdouble *params);
void glGetVertexAttribfvARB(GLuint index, GLenum pname, GLfloat *params);
void glGetVertexAttribivARB(GLuint index, GLenum pname, GLint *params);
void glDeleteObjectARB(GLhandleARB obj);
GLhandleARB glGetHandleARB(GLenum pname);
void glDetachObjectARB(GLhandleARB containerObj, GLhandleARB attachedObj);
GLhandleARB glCreateShaderObjectARB(GLenum shaderType);
void glShaderSourceARB(GLhandleARB shaderObj, GLsizei count, const GLcharARB **string, const GLint *length);
void glCompileShaderARB(GLhandleARB shaderObj);
GLhandleARB glCreateProgramObjectARB(void);
void glAttachObjectARB(GLhandleARB containerObj, GLhandleARB obj);
void glLinkProgramARB(GLhandleARB programObj);
void glUseProgramObjectARB(GLhandleARB programObj);
void glValidateProgramARB(GLhandleARB programObj);
void glUniform1fARB(GLint location, GLfloat v0);
void glUniform2fARB(GLint location, GLfloat v0, GLfloat v1);
void glUniform3fARB(GLint location, GLfloat v0, GLfloat v1, GLfloat v2);
void glUniform4fARB(GLint location, GLfloat v0, GLfloat v1, GLfloat v2, GLfloat v3);
void glUniform1iARB(GLint location, GLint v0);
void glUniform2iARB(GLint location, GLint v0, GLint v1);
void glUniform3iARB(GLint location, GLint v0, GLint v1, GLint v2);
void glUniform4iARB(GLint location, GLint v0, GLint v1, GLint v2, GLint v3);
void glUniform1fvARB(GLint location, GLsizei count, const GLfloat *value);
void glUniform2fvARB(GLint location, GLsizei count, const GLfloat *value);
void glUniform3fvARB(GLint location, GLsizei count, const GLfloat *value);
void glUniform4fvARB(GLint location, GLsizei count, const GLfloat *value);
void glUniform1ivARB(GLint location, GLsizei count, const GLint *value);
void glUniform2ivARB(GLint location, GLsizei count, const GLint *value);
void glUniform3ivARB(GLint location, GLsizei count, const GLint *value);
void glUniform4ivARB(GLint location, GLsizei count, const GLint *value);
void glUniformMatrix2fvARB(GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix3fvARB(GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix4fvARB(GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glGetObjectParameterfvARB(GLhandleARB obj, GLenum pname, GLfloat *params);
void glGetObjectParameterivARB(GLhandleARB obj, GLenum pname, GLint *params);
void glGetInfoLogARB(GLhandleARB obj, GLsizei maxLength, GLsizei *length, GLcharARB *infoLog);
void glGetAttachedObjectsARB(GLhandleARB containerObj, GLsizei maxCount, GLsizei *count, GLhandleARB *obj);
GLint glGetUniformLocationARB(GLhandleARB programObj, const GLcharARB *name);
void glGetActiveUniformARB(GLhandleARB programObj, GLuint index, GLsizei maxLength, GLsizei *length, GLint *size, GLenum *type, GLcharARB *name);
void glGetUniformfvARB(GLhandleARB programObj, GLint location, GLfloat *params);
void glGetUniformivARB(GLhandleARB programObj, GLint location, GLint *params);
void glGetShaderSourceARB(GLhandleARB obj, GLsizei maxLength, GLsizei *length, GLcharARB *source);
void glBindAttribLocationARB(GLhandleARB programObj, GLuint index, const GLcharARB *name);
void glGetActiveAttribARB(GLhandleARB programObj, GLuint index, GLsizei maxLength, GLsizei *length, GLint *size, GLenum *type, GLcharARB *name);
GLint glGetAttribLocationARB(GLhandleARB programObj, const GLcharARB *name);
void glBindBufferARB(GLenum target, GLuint buffer);
void glDeleteBuffersARB(GLsizei n, const GLuint *buffers);
void glGenBuffersARB(GLsizei n, GLuint *buffers);
GLboolean glIsBufferARB(GLuint buffer);
void glBufferDataARB(GLenum target, GLsizeiptrARB size, const GLvoid *data, GLenum usage);
void glBufferSubDataARB(GLenum target, GLintptrARB offset, GLsizeiptrARB size, const GLvoid *data);
void glGetBufferSubDataARB(GLenum target, GLintptrARB offset, GLsizeiptrARB size, GLvoid *data);
GLvoid *glMapBufferARB(GLenum target, GLenum access);
GLboolean glUnmapBufferARB(GLenum target);
void glGetBufferParameterivARB(GLenum target, GLenum pname, GLint *params);
void glGetBufferPointervARB(GLenum target, GLenum pname, GLvoid **params);
void glDrawBuffersARB(GLsizei n, const GLenum *bufs);
void glClampColorARB(GLenum target, GLenum clamp);
void glDrawArraysInstancedARB(GLenum mode, GLint first, GLsizei count, GLsizei primcount);
void glDrawElementsInstancedARB(GLenum mode, GLsizei count, GLenum type, const GLvoid *indices, GLsizei primcount);
void glVertexAttribDivisorARB(GLuint index, GLuint divisor);
void glGetUniformIndices(GLuint program, GLsizei uniformCount, const GLchar** uniformNames, GLuint* uniformIndices);
void glGetActiveUniformsiv(GLuint program, GLsizei uniformCount, const GLuint* uniformIndices, GLenum pname, GLint* params);
void glGetActiveUniformName(GLuint program, GLuint uniformIndex, GLsizei bufSize, GLsizei* length, GLchar* uniformName);
GLuint glGetUniformBlockIndex(GLuint program, const GLchar* uniformBlockName);
void glGetActiveUniformBlockiv(GLuint program, GLuint uniformBlockIndex, GLenum pname, GLint* params);
void glGetActiveUniformBlockName(GLuint program, GLuint uniformBlockIndex, GLsizei bufSize, GLsizei* length, GLchar* uniformBlockName);
void glBindBufferRange(GLenum target, GLuint index, GLuint buffer, GLintptr offset, GLsizeiptr size);
void glBindBufferBase(GLenum target, GLuint index, GLuint buffer);
void glGetIntegeri_v(GLenum pname, GLuint index, GLint* data);
void glUniformBlockBinding(GLuint program, GLuint uniformBlockIndex, GLuint uniformBlockBinding);
void glBlendColorEXT (GLclampf, GLclampf, GLclampf, GLclampf);
void glBlendEquationEXT (GLenum);
void glLockArraysEXT (GLint, GLsizei);
void glUnlockArraysEXT (void);
void glDrawRangeElementsEXT (GLenum, GLuint, GLuint, GLsizei, GLenum, const GLvoid *);
void glSecondaryColor3bEXT (GLbyte, GLbyte, GLbyte);
void glSecondaryColor3bvEXT (const GLbyte *);
void glSecondaryColor3dEXT (GLdouble, GLdouble, GLdouble);
void glSecondaryColor3dvEXT (const GLdouble *);
void glSecondaryColor3fEXT (GLfloat, GLfloat, GLfloat);
void glSecondaryColor3fvEXT (const GLfloat *);
void glSecondaryColor3iEXT (GLint, GLint, GLint);
void glSecondaryColor3ivEXT (const GLint *);
void glSecondaryColor3sEXT (GLshort, GLshort, GLshort);
void glSecondaryColor3svEXT (const GLshort *);
void glSecondaryColor3ubEXT (GLubyte, GLubyte, GLubyte);
void glSecondaryColor3ubvEXT (const GLubyte *);
void glSecondaryColor3uiEXT (GLuint, GLuint, GLuint);
void glSecondaryColor3uivEXT (const GLuint *);
void glSecondaryColor3usEXT (GLushort, GLushort, GLushort);
void glSecondaryColor3usvEXT (const GLushort *);
void glSecondaryColorPointerEXT (GLint, GLenum, GLsizei, const GLvoid *);
void glMultiDrawArraysEXT (GLenum, const GLint *, const GLsizei *, GLsizei);
void glMultiDrawElementsEXT (GLenum, const GLsizei *, GLenum, const GLvoid* *, GLsizei);
void glFogCoordfEXT (GLfloat);
void glFogCoordfvEXT (const GLfloat *);
void glFogCoorddEXT (GLdouble);
void glFogCoorddvEXT (const GLdouble *);
void glFogCoordPointerEXT (GLenum, GLsizei, const GLvoid *);
void glBlendFuncSeparateEXT (GLenum, GLenum, GLenum, GLenum);
void glActiveStencilFaceEXT(GLenum face);
void glDepthBoundsEXT(GLclampd zmin, GLclampd zmax);
void glBlendEquationSeparateEXT(GLenum modeRGB, GLenum modeAlpha);
GLboolean glIsRenderbufferEXT(GLuint renderbuffer);
void glBindRenderbufferEXT(GLenum target, GLuint renderbuffer);
void glDeleteRenderbuffersEXT(GLsizei n, const GLuint *renderbuffers);
void glGenRenderbuffersEXT(GLsizei n, GLuint *renderbuffers);
void glRenderbufferStorageEXT(GLenum target, GLenum internalformat, GLsizei width, GLsizei height);
void glGetRenderbufferParameterivEXT(GLenum target, GLenum pname, GLint *params);
GLboolean glIsFramebufferEXT(GLuint framebuffer);
void glBindFramebufferEXT(GLenum target, GLuint framebuffer);
void glDeleteFramebuffersEXT(GLsizei n, const GLuint *framebuffers);
void glGenFramebuffersEXT(GLsizei n, GLuint *framebuffers);
GLenum glCheckFramebufferStatusEXT(GLenum target);
void glFramebufferTexture1DEXT(GLenum target, GLenum attachment, GLenum textarget, GLuint texture, GLint level);
void glFramebufferTexture2DEXT(GLenum target, GLenum attachment, GLenum textarget, GLuint texture, GLint level);
void glFramebufferTexture3DEXT(GLenum target, GLenum attachment, GLenum textarget, GLuint texture, GLint level, GLint zoffset);
void glFramebufferRenderbufferEXT(GLenum target, GLenum attachment, GLenum renderbuffertarget, GLuint renderbuffer);
void glGetFramebufferAttachmentParameterivEXT(GLenum target, GLenum attachment, GLenum pname, GLint *params);
void glGenerateMipmapEXT(GLenum target);
void glBlitFramebufferEXT(GLint srcX0, GLint srcY0, GLint srcX1, GLint srcY1, GLint dstX0, GLint dstY0, GLint dstX1, GLint dstY1, GLbitfield mask, GLenum filter);
void glRenderbufferStorageMultisampleEXT(GLenum target, GLsizei samples, GLenum internalformat, GLsizei width, GLsizei height);
void glProgramParameteriEXT(GLuint program, GLenum pname, GLint value);
void glFramebufferTextureEXT(GLenum target, GLenum attachment, GLuint texture, GLint level);
void glFramebufferTextureFaceEXT(GLenum target, GLenum attachment, GLuint texture, GLint level, GLenum face);
void glFramebufferTextureLayerEXT(GLenum target, GLenum attachment, GLuint texture, GLint level, GLint layer);
GLboolean glIsRenderbuffer (GLuint);
void glBindRenderbuffer (GLenum, GLuint);
void glDeleteRenderbuffers (GLsizei, const GLuint *);
void glGenRenderbuffers (GLsizei, GLuint *);
void glRenderbufferStorage (GLenum, GLenum, GLsizei, GLsizei);
void glGetRenderbufferParameteriv (GLenum, GLenum, GLint *);
GLboolean glIsFramebuffer (GLuint);
void glBindFramebuffer (GLenum, GLuint);
void glDeleteFramebuffers (GLsizei, const GLuint *);
void glGenFramebuffers (GLsizei, GLuint *);
GLenum glCheckFramebufferStatus (GLenum);
void glFramebufferTexture1D (GLenum, GLenum, GLenum, GLuint, GLint);
void glFramebufferTexture2D (GLenum, GLenum, GLenum, GLuint, GLint);
void glFramebufferTexture3D (GLenum, GLenum, GLenum, GLuint, GLint, GLint);
void glFramebufferRenderbuffer (GLenum, GLenum, GLenum, GLuint);
void glGetFramebufferAttachmentParameteriv (GLenum, GLenum, GLenum, GLint *);
void glGenerateMipmap (GLenum);
void glBlitFramebuffer (GLint, GLint, GLint, GLint, GLint, GLint, GLint, GLint, GLbitfield, GLenum);
void glRenderbufferStorageMultisample (GLenum, GLsizei, GLenum, GLsizei, GLsizei);
void glFramebufferTextureLayer (GLenum, GLenum, GLuint, GLint, GLint);
void glBindBufferRangeEXT(GLenum target, GLuint index, GLuint buffer, GLintptr offset, GLsizeiptr size);
void glBindBufferOffsetEXT(GLenum target, GLuint index, GLuint buffer, GLintptr offset);
void glBindBufferBaseEXT(GLenum target, GLuint index, GLuint buffer);
void glBeginTransformFeedbackEXT(GLenum primitiveMode);
void glEndTransformFeedbackEXT(void);
void glTransformFeedbackVaryingsEXT(GLuint program, GLsizei count, const GLchar **varyings, GLenum bufferMode);
void glGetTransformFeedbackVaryingEXT(GLuint program, GLuint index, GLsizei bufSize, GLsizei *length, GLsizei *size, GLenum *type, GLchar *name);
void glGetIntegerIndexedvEXT(GLenum param, GLuint index, GLint *values);
void glGetBooleanIndexedvEXT(GLenum param, GLuint index, GLboolean *values);
void glUniformBufferEXT(GLuint program, GLint location, GLuint buffer);
GLint glGetUniformBufferSizeEXT(GLuint program, GLint location);
GLintptr glGetUniformOffsetEXT(GLuint program, GLint location);
void glClearColorIiEXT( GLint r, GLint g, GLint b, GLint a );
void glClearColorIuiEXT( GLuint r, GLuint g, GLuint b, GLuint a );
void glTexParameterIivEXT( GLenum target, GLenum pname, GLint *params );
void glTexParameterIuivEXT( GLenum target, GLenum pname, GLuint *params );
void glGetTexParameterIivEXT( GLenum target, GLenum pname, GLint *params);
void glGetTexParameterIuivEXT( GLenum target, GLenum pname, GLuint *params);
void glVertexAttribI1iEXT(GLuint index, GLint x);
void glVertexAttribI2iEXT(GLuint index, GLint x, GLint y);
void glVertexAttribI3iEXT(GLuint index, GLint x, GLint y, GLint z);
void glVertexAttribI4iEXT(GLuint index, GLint x, GLint y, GLint z, GLint w);
void glVertexAttribI1uiEXT(GLuint index, GLuint x);
void glVertexAttribI2uiEXT(GLuint index, GLuint x, GLuint y);
void glVertexAttribI3uiEXT(GLuint index, GLuint x, GLuint y, GLuint z);
void glVertexAttribI4uiEXT(GLuint index, GLuint x, GLuint y, GLuint z, GLuint w);
void glVertexAttribI1ivEXT(GLuint index, const GLint *v);
void glVertexAttribI2ivEXT(GLuint index, const GLint *v);
void glVertexAttribI3ivEXT(GLuint index, const GLint *v);
void glVertexAttribI4ivEXT(GLuint index, const GLint *v);
void glVertexAttribI1uivEXT(GLuint index, const GLuint *v);
void glVertexAttribI2uivEXT(GLuint index, const GLuint *v);
void glVertexAttribI3uivEXT(GLuint index, const GLuint *v);
void glVertexAttribI4uivEXT(GLuint index, const GLuint *v);
void glVertexAttribI4bvEXT(GLuint index, const GLbyte *v);
void glVertexAttribI4svEXT(GLuint index, const GLshort *v);
void glVertexAttribI4ubvEXT(GLuint index, const GLubyte *v);
void glVertexAttribI4usvEXT(GLuint index, const GLushort *v);
void glVertexAttribIPointerEXT(GLuint index, GLint size, GLenum type, GLsizei stride, const GLvoid *pointer);
void glGetVertexAttribIivEXT(GLuint index, GLenum pname, GLint *params);
void glGetVertexAttribIuivEXT(GLuint index, GLenum pname, GLuint *params);
void glUniform1uiEXT(GLint location, GLuint v0);
void glUniform2uiEXT(GLint location, GLuint v0, GLuint v1);
void glUniform3uiEXT(GLint location, GLuint v0, GLuint v1, GLuint v2);
void glUniform4uiEXT(GLint location, GLuint v0, GLuint v1, GLuint v2, GLuint v3);
void glUniform1uivEXT(GLint location, GLsizei count, const GLuint *value);
void glUniform2uivEXT(GLint location, GLsizei count, const GLuint *value);
void glUniform3uivEXT(GLint location, GLsizei count, const GLuint *value);
void glUniform4uivEXT(GLint location, GLsizei count, const GLuint *value);
void glGetUniformuivEXT(GLuint program, GLint location, GLuint *params);
void glBindFragDataLocationEXT(GLuint program, GLuint colorNumber, const GLchar *name);
GLint glGetFragDataLocationEXT(GLuint program, const GLchar *name);
void glColorMaskIndexedEXT(GLuint index, GLboolean r, GLboolean g, GLboolean b, GLboolean a);
void glEnableIndexedEXT(GLenum target, GLuint index);
void glDisableIndexedEXT(GLenum target, GLuint index);
GLboolean glIsEnabledIndexedEXT(GLenum target, GLuint index);
void glProvokingVertexEXT(GLenum mode);
void glTextureRangeAPPLE(GLenum target, GLsizei length, const GLvoid *pointer);
void glGetTexParameterPointervAPPLE(GLenum target, GLenum pname, GLvoid **params);
void glVertexArrayRangeAPPLE(GLsizei length, const GLvoid *pointer);
void glFlushVertexArrayRangeAPPLE(GLsizei length, const GLvoid *pointer);
void glVertexArrayParameteriAPPLE(GLenum pname, GLint param);
void glBindVertexArrayAPPLE(GLuint id);
void glDeleteVertexArraysAPPLE(GLsizei n, const GLuint *ids);
void glGenVertexArraysAPPLE(GLsizei n, GLuint *ids);
GLboolean glIsVertexArrayAPPLE(GLuint id);
void glGenFencesAPPLE(GLsizei n, GLuint *fences);
void glDeleteFencesAPPLE(GLsizei n, const GLuint *fences);
void glSetFenceAPPLE(GLuint fence);
GLboolean glIsFenceAPPLE(GLuint fence);
GLboolean glTestFenceAPPLE(GLuint fence);
void glFinishFenceAPPLE(GLuint fence);
GLboolean glTestObjectAPPLE(GLenum object, GLuint name);
void glFinishObjectAPPLE(GLenum object, GLuint name);
void glElementPointerAPPLE(GLenum type, const GLvoid *pointer);
void glDrawElementArrayAPPLE(GLenum mode, GLint first, GLsizei count);
void glDrawRangeElementArrayAPPLE(GLenum mode, GLuint start, GLuint end, GLint first, GLsizei count);
void glMultiDrawElementArrayAPPLE(GLenum mode, const GLint *first, const GLsizei *count, GLsizei primcount);
void glMultiDrawRangeElementArrayAPPLE(GLenum mode, GLuint start, GLuint end, const GLint *first, const GLsizei *count, GLsizei primcount);
void glFlushRenderAPPLE(void);
void glFinishRenderAPPLE(void);
void glSwapAPPLE(void);
void glEnableVertexAttribAPPLE(GLuint index, GLenum pname);
void glDisableVertexAttribAPPLE(GLuint index, GLenum pname);
GLboolean glIsVertexAttribEnabledAPPLE(GLuint index, GLenum pname);
void glMapVertexAttrib1dAPPLE(GLuint index, GLuint size, GLdouble u1, GLdouble u2, GLint stride, GLint order, const GLdouble *points);
void glMapVertexAttrib1fAPPLE(GLuint index, GLuint size, GLfloat u1, GLfloat u2, GLint stride, GLint order, const GLfloat *points);
void glMapVertexAttrib2dAPPLE(GLuint index, GLuint size, GLdouble u1, GLdouble u2, GLint ustride, GLint uorder, GLdouble v1, GLdouble v2, GLint vstride, GLint vorder, const GLdouble *points);
void glMapVertexAttrib2fAPPLE(GLuint index, GLuint size, GLfloat u1, GLfloat u2, GLint ustride, GLint uorder, GLfloat v1, GLfloat v2, GLint vstride, GLint vorder, const GLfloat *points);
void glBufferParameteriAPPLE(GLenum target, GLenum pname, GLint param);
void glFlushMappedBufferRangeAPPLE(GLenum target, GLintptr offset, GLsizeiptr size);
GLenum glObjectPurgeableAPPLE(GLenum objectType, GLuint name, GLenum option);
GLenum glObjectUnpurgeableAPPLE(GLenum objectType, GLuint name, GLenum option);
void glGetObjectParameterivAPPLE(GLenum objectType, GLuint name, GLenum pname, GLint* params);
void glPNTrianglesiATI(GLenum pname, GLint param);
void glPNTrianglesfATI(GLenum pname, GLfloat param);
void glBlendEquationSeparateATI(GLenum equationRGB, GLenum equationAlpha);
void glStencilOpSeparateATI(GLenum face, GLenum sfail, GLenum dpfail, GLenum dppass);
void glStencilFuncSeparateATI(GLenum frontfunc, GLenum backfunc, GLint ref, GLuint mask);
void glPNTrianglesiATIX(GLenum pname, GLint param);
void glPNTrianglesfATIX(GLenum pname, GLfloat param);
void glPointParameteriNV(GLenum pname, GLint param);
void glPointParameterivNV(GLenum pname, const GLint *params);
void glBeginConditionalRenderNV (GLuint id, GLenum mode);
void glEndConditionalRenderNV (void);
void glAccum (GLenum op, GLfloat value);
void glAlphaFunc (GLenum func, GLclampf ref);
GLboolean glAreTexturesResident (GLsizei n, const GLuint *textures, GLboolean *residences);
void glArrayElement (GLint i);
void glBegin (GLenum mode);
void glBindTexture (GLenum target, GLuint texture);
void glBitmap (GLsizei width, GLsizei height, GLfloat xorig, GLfloat yorig, GLfloat xmove, GLfloat ymove, const GLubyte *bitmap);
void glBlendColor (GLclampf red, GLclampf green, GLclampf blue, GLclampf alpha);
void glBlendEquation (GLenum mode);
void glBlendEquationSeparate(GLenum modeRGB, GLenum modeAlpha);
void glBlendFunc (GLenum sfactor, GLenum dfactor);
void glCallList (GLuint list);
void glCallLists (GLsizei n, GLenum type, const GLvoid *lists);
void glClear (GLbitfield mask);
void glClearAccum (GLfloat red, GLfloat green, GLfloat blue, GLfloat alpha);
void glClearColor (GLclampf red, GLclampf green, GLclampf blue, GLclampf alpha);
void glClearDepth (GLclampd depth);
void glClearIndex (GLfloat c);
void glClearStencil (GLint s);
void glClipPlane (GLenum plane, const GLdouble *equation);
void glColor3b (GLbyte red, GLbyte green, GLbyte blue);
void glColor3bv (const GLbyte *v);
void glColor3d (GLdouble red, GLdouble green, GLdouble blue);
void glColor3dv (const GLdouble *v);
void glColor3f (GLfloat red, GLfloat green, GLfloat blue);
void glColor3fv (const GLfloat *v);
void glColor3i (GLint red, GLint green, GLint blue);
void glColor3iv (const GLint *v);
void glColor3s (GLshort red, GLshort green, GLshort blue);
void glColor3sv (const GLshort *v);
void glColor3ub (GLubyte red, GLubyte green, GLubyte blue);
void glColor3ubv (const GLubyte *v);
void glColor3ui (GLuint red, GLuint green, GLuint blue);
void glColor3uiv (const GLuint *v);
void glColor3us (GLushort red, GLushort green, GLushort blue);
void glColor3usv (const GLushort *v);
void glColor4b (GLbyte red, GLbyte green, GLbyte blue, GLbyte alpha);
void glColor4bv (const GLbyte *v);
void glColor4d (GLdouble red, GLdouble green, GLdouble blue, GLdouble alpha);
void glColor4dv (const GLdouble *v);
void glColor4f (GLfloat red, GLfloat green, GLfloat blue, GLfloat alpha);
void glColor4fv (const GLfloat *v);
void glColor4i (GLint red, GLint green, GLint blue, GLint alpha);
void glColor4iv (const GLint *v);
void glColor4s (GLshort red, GLshort green, GLshort blue, GLshort alpha);
void glColor4sv (const GLshort *v);
void glColor4ub (GLubyte red, GLubyte green, GLubyte blue, GLubyte alpha);
void glColor4ubv (const GLubyte *v);
void glColor4ui (GLuint red, GLuint green, GLuint blue, GLuint alpha);
void glColor4uiv (const GLuint *v);
void glColor4us (GLushort red, GLushort green, GLushort blue, GLushort alpha);
void glColor4usv (const GLushort *v);
void glColorMask (GLboolean red, GLboolean green, GLboolean blue, GLboolean alpha);
void glColorMaterial (GLenum face, GLenum mode);
void glColorPointer (GLint size, GLenum type, GLsizei stride, const GLvoid *pointer);
void glColorSubTable (GLenum target, GLsizei start, GLsizei count, GLenum format, GLenum type, const GLvoid *data);
void glColorTable (GLenum target, GLenum internalformat, GLsizei width, GLenum format, GLenum type, const GLvoid *table);
void glColorTableParameterfv (GLenum target, GLenum pname, const GLfloat *params);
void glColorTableParameteriv (GLenum target, GLenum pname, const GLint *params);
void glConvolutionFilter1D (GLenum target, GLenum internalformat, GLsizei width, GLenum format, GLenum type, const GLvoid *image);
void glConvolutionFilter2D (GLenum target, GLenum internalformat, GLsizei width, GLsizei height, GLenum format, GLenum type, const GLvoid *image);
void glConvolutionParameterf (GLenum target, GLenum pname, GLfloat params);
void glConvolutionParameterfv (GLenum target, GLenum pname, const GLfloat *params);
void glConvolutionParameteri (GLenum target, GLenum pname, GLint params);
void glConvolutionParameteriv (GLenum target, GLenum pname, const GLint *params);
void glCopyColorSubTable (GLenum target, GLsizei start, GLint x, GLint y, GLsizei width);
void glCopyColorTable (GLenum target, GLenum internalformat, GLint x, GLint y, GLsizei width);
void glCopyConvolutionFilter1D (GLenum target, GLenum internalformat, GLint x, GLint y, GLsizei width);
void glCopyConvolutionFilter2D (GLenum target, GLenum internalformat, GLint x, GLint y, GLsizei width, GLsizei height);
void glCopyPixels (GLint x, GLint y, GLsizei width, GLsizei height, GLenum type);
void glCopyTexImage1D (GLenum target, GLint level, GLenum internalformat, GLint x, GLint y, GLsizei width, GLint border);
void glCopyTexImage2D (GLenum target, GLint level, GLenum internalformat, GLint x, GLint y, GLsizei width, GLsizei height, GLint border);
void glCopyTexSubImage1D (GLenum target, GLint level, GLint xoffset, GLint x, GLint y, GLsizei width);
void glCopyTexSubImage2D (GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint x, GLint y, GLsizei width, GLsizei height);
void glCopyTexSubImage3D (GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLint x, GLint y, GLsizei width, GLsizei height);
void glCullFace (GLenum mode);
void glDeleteLists (GLuint list, GLsizei range);
void glDeleteTextures (GLsizei n, const GLuint *textures);
void glDepthFunc (GLenum func);
void glDepthMask (GLboolean flag);
void glDepthRange (GLclampd zNear, GLclampd zFar);
void glDisable (GLenum cap);
void glDisableClientState (GLenum array);
void glDrawArrays (GLenum mode, GLint first, GLsizei count);
void glDrawBuffer (GLenum mode);
void glDrawElements (GLenum mode, GLsizei count, GLenum type, const GLvoid *indices);
void glDrawPixels (GLsizei width, GLsizei height, GLenum format, GLenum type, const GLvoid *pixels);
void glDrawRangeElements (GLenum mode, GLuint start, GLuint end, GLsizei count, GLenum type, const GLvoid *indices);
void glEdgeFlag (GLboolean flag);
void glEdgeFlagPointer (GLsizei stride, const GLvoid *pointer);
void glEdgeFlagv (const GLboolean *flag);
void glEnable (GLenum cap);
void glEnableClientState (GLenum array);
void glEnd (void);
void glEndList (void);
void glEvalCoord1d (GLdouble u);
void glEvalCoord1dv (const GLdouble *u);
void glEvalCoord1f (GLfloat u);
void glEvalCoord1fv (const GLfloat *u);
void glEvalCoord2d (GLdouble u, GLdouble v);
void glEvalCoord2dv (const GLdouble *u);
void glEvalCoord2f (GLfloat u, GLfloat v);
void glEvalCoord2fv (const GLfloat *u);
void glEvalMesh1 (GLenum mode, GLint i1, GLint i2);
void glEvalMesh2 (GLenum mode, GLint i1, GLint i2, GLint j1, GLint j2);
void glEvalPoint1 (GLint i);
void glEvalPoint2 (GLint i, GLint j);
void glFeedbackBuffer (GLsizei size, GLenum type, GLfloat *buffer);
void glFinish (void);
void glFlush (void);
void glFogf (GLenum pname, GLfloat param);
void glFogfv (GLenum pname, const GLfloat *params);
void glFogi (GLenum pname, GLint param);
void glFogiv (GLenum pname, const GLint *params);
void glFrontFace (GLenum mode);
void glFrustum (GLdouble left, GLdouble right, GLdouble bottom, GLdouble top, GLdouble zNear, GLdouble zFar);
GLuint glGenLists (GLsizei range);
void glGenTextures (GLsizei n, GLuint *textures);
void glGetBooleanv (GLenum pname, GLboolean *params);
void glGetClipPlane (GLenum plane, GLdouble *equation);
void glGetColorTable (GLenum target, GLenum format, GLenum type, GLvoid *table);
void glGetColorTableParameterfv (GLenum target, GLenum pname, GLfloat *params);
void glGetColorTableParameteriv (GLenum target, GLenum pname, GLint *params);
void glGetConvolutionFilter (GLenum target, GLenum format, GLenum type, GLvoid *image);
void glGetConvolutionParameterfv (GLenum target, GLenum pname, GLfloat *params);
void glGetConvolutionParameteriv (GLenum target, GLenum pname, GLint *params);
void glGetDoublev (GLenum pname, GLdouble *params);
GLenum glGetError (void);
void glGetFloatv (GLenum pname, GLfloat *params);
void glGetHistogram (GLenum target, GLboolean reset, GLenum format, GLenum type, GLvoid *values);
void glGetHistogramParameterfv (GLenum target, GLenum pname, GLfloat *params);
void glGetHistogramParameteriv (GLenum target, GLenum pname, GLint *params);
void glGetIntegerv (GLenum pname, GLint *params);
void glGetLightfv (GLenum light, GLenum pname, GLfloat *params);
void glGetLightiv (GLenum light, GLenum pname, GLint *params);
void glGetMapdv (GLenum target, GLenum query, GLdouble *v);
void glGetMapfv (GLenum target, GLenum query, GLfloat *v);
void glGetMapiv (GLenum target, GLenum query, GLint *v);
void glGetMaterialfv (GLenum face, GLenum pname, GLfloat *params);
void glGetMaterialiv (GLenum face, GLenum pname, GLint *params);
void glGetMinmax (GLenum target, GLboolean reset, GLenum format, GLenum type, GLvoid *values);
void glGetMinmaxParameterfv (GLenum target, GLenum pname, GLfloat *params);
void glGetMinmaxParameteriv (GLenum target, GLenum pname, GLint *params);
void glGetPixelMapfv (GLenum map, GLfloat *values);
void glGetPixelMapuiv (GLenum map, GLuint *values);
void glGetPixelMapusv (GLenum map, GLushort *values);
void glGetPointerv (GLenum pname, GLvoid* *params);
void glGetPolygonStipple (GLubyte *mask);
void glGetSeparableFilter (GLenum target, GLenum format, GLenum type, GLvoid *row, GLvoid *column, GLvoid *span);
const GLubyte * glGetString (GLenum name);
void glGetTexEnvfv (GLenum target, GLenum pname, GLfloat *params);
void glGetTexEnviv (GLenum target, GLenum pname, GLint *params);
void glGetTexGendv (GLenum coord, GLenum pname, GLdouble *params);
void glGetTexGenfv (GLenum coord, GLenum pname, GLfloat *params);
void glGetTexGeniv (GLenum coord, GLenum pname, GLint *params);
void glGetTexImage (GLenum target, GLint level, GLenum format, GLenum type, GLvoid *pixels);
void glGetTexLevelParameterfv (GLenum target, GLint level, GLenum pname, GLfloat *params);
void glGetTexLevelParameteriv (GLenum target, GLint level, GLenum pname, GLint *params);
void glGetTexParameterfv (GLenum target, GLenum pname, GLfloat *params);
void glGetTexParameteriv (GLenum target, GLenum pname, GLint *params);
void glHint (GLenum target, GLenum mode);
void glHistogram (GLenum target, GLsizei width, GLenum internalformat, GLboolean sink);
void glIndexMask (GLuint mask);
void glIndexPointer (GLenum type, GLsizei stride, const GLvoid *pointer);
void glIndexd (GLdouble c);
void glIndexdv (const GLdouble *c);
void glIndexf (GLfloat c);
void glIndexfv (const GLfloat *c);
void glIndexi (GLint c);
void glIndexiv (const GLint *c);
void glIndexs (GLshort c);
void glIndexsv (const GLshort *c);
void glIndexub (GLubyte c);
void glIndexubv (const GLubyte *c);
void glInitNames (void);
void glInterleavedArrays (GLenum format, GLsizei stride, const GLvoid *pointer);
GLboolean glIsEnabled (GLenum cap);
GLboolean glIsList (GLuint list);
GLboolean glIsTexture (GLuint texture);
void glLightModelf (GLenum pname, GLfloat param);
void glLightModelfv (GLenum pname, const GLfloat *params);
void glLightModeli (GLenum pname, GLint param);
void glLightModeliv (GLenum pname, const GLint *params);
void glLightf (GLenum light, GLenum pname, GLfloat param);
void glLightfv (GLenum light, GLenum pname, const GLfloat *params);
void glLighti (GLenum light, GLenum pname, GLint param);
void glLightiv (GLenum light, GLenum pname, const GLint *params);
void glLineStipple (GLint factor, GLushort pattern);
void glLineWidth (GLfloat width);
void glListBase (GLuint base);
void glLoadIdentity (void);
void glLoadMatrixd (const GLdouble *m);
void glLoadMatrixf (const GLfloat *m);
void glLoadName (GLuint name);
void glLogicOp (GLenum opcode);
void glMap1d (GLenum target, GLdouble u1, GLdouble u2, GLint stride, GLint order, const GLdouble *points);
void glMap1f (GLenum target, GLfloat u1, GLfloat u2, GLint stride, GLint order, const GLfloat *points);
void glMap2d (GLenum target, GLdouble u1, GLdouble u2, GLint ustride, GLint uorder, GLdouble v1, GLdouble v2, GLint vstride, GLint vorder, const GLdouble *points);
void glMap2f (GLenum target, GLfloat u1, GLfloat u2, GLint ustride, GLint uorder, GLfloat v1, GLfloat v2, GLint vstride, GLint vorder, const GLfloat *points);
void glMapGrid1d (GLint un, GLdouble u1, GLdouble u2);
void glMapGrid1f (GLint un, GLfloat u1, GLfloat u2);
void glMapGrid2d (GLint un, GLdouble u1, GLdouble u2, GLint vn, GLdouble v1, GLdouble v2);
void glMapGrid2f (GLint un, GLfloat u1, GLfloat u2, GLint vn, GLfloat v1, GLfloat v2);
void glMaterialf (GLenum face, GLenum pname, GLfloat param);
void glMaterialfv (GLenum face, GLenum pname, const GLfloat *params);
void glMateriali (GLenum face, GLenum pname, GLint param);
void glMaterialiv (GLenum face, GLenum pname, const GLint *params);
void glMatrixMode (GLenum mode);
void glMinmax (GLenum target, GLenum internalformat, GLboolean sink);
void glMultMatrixd (const GLdouble *m);
void glMultMatrixf (const GLfloat *m);
void glNewList (GLuint list, GLenum mode);
void glNormal3b (GLbyte nx, GLbyte ny, GLbyte nz);
void glNormal3bv (const GLbyte *v);
void glNormal3d (GLdouble nx, GLdouble ny, GLdouble nz);
void glNormal3dv (const GLdouble *v);
void glNormal3f (GLfloat nx, GLfloat ny, GLfloat nz);
void glNormal3fv (const GLfloat *v);
void glNormal3i (GLint nx, GLint ny, GLint nz);
void glNormal3iv (const GLint *v);
void glNormal3s (GLshort nx, GLshort ny, GLshort nz);
void glNormal3sv (const GLshort *v);
void glNormalPointer (GLenum type, GLsizei stride, const GLvoid *pointer);
void glOrtho (GLdouble left, GLdouble right, GLdouble bottom, GLdouble top, GLdouble zNear, GLdouble zFar);
void glPassThrough (GLfloat token);
void glPixelMapfv (GLenum map, GLint mapsize, const GLfloat *values);
void glPixelMapuiv (GLenum map, GLint mapsize, const GLuint *values);
void glPixelMapusv (GLenum map, GLint mapsize, const GLushort *values);
void glPixelStoref (GLenum pname, GLfloat param);
void glPixelStorei (GLenum pname, GLint param);
void glPixelTransferf (GLenum pname, GLfloat param);
void glPixelTransferi (GLenum pname, GLint param);
void glPixelZoom (GLfloat xfactor, GLfloat yfactor);
void glPointSize (GLfloat size);
void glPolygonMode (GLenum face, GLenum mode);
void glPolygonOffset (GLfloat factor, GLfloat units);
void glPolygonStipple (const GLubyte *mask);
void glPopAttrib (void);
void glPopClientAttrib (void);
void glPopMatrix (void);
void glPopName (void);
void glPrioritizeTextures (GLsizei n, const GLuint *textures, const GLclampf *priorities);
void glPushAttrib (GLbitfield mask);
void glPushClientAttrib (GLbitfield mask);
void glPushMatrix (void);
void glPushName (GLuint name);
void glRasterPos2d (GLdouble x, GLdouble y);
void glRasterPos2dv (const GLdouble *v);
void glRasterPos2f (GLfloat x, GLfloat y);
void glRasterPos2fv (const GLfloat *v);
void glRasterPos2i (GLint x, GLint y);
void glRasterPos2iv (const GLint *v);
void glRasterPos2s (GLshort x, GLshort y);
void glRasterPos2sv (const GLshort *v);
void glRasterPos3d (GLdouble x, GLdouble y, GLdouble z);
void glRasterPos3dv (const GLdouble *v);
void glRasterPos3f (GLfloat x, GLfloat y, GLfloat z);
void glRasterPos3fv (const GLfloat *v);
void glRasterPos3i (GLint x, GLint y, GLint z);
void glRasterPos3iv (const GLint *v);
void glRasterPos3s (GLshort x, GLshort y, GLshort z);
void glRasterPos3sv (const GLshort *v);
void glRasterPos4d (GLdouble x, GLdouble y, GLdouble z, GLdouble w);
void glRasterPos4dv (const GLdouble *v);
void glRasterPos4f (GLfloat x, GLfloat y, GLfloat z, GLfloat w);
void glRasterPos4fv (const GLfloat *v);
void glRasterPos4i (GLint x, GLint y, GLint z, GLint w);
void glRasterPos4iv (const GLint *v);
void glRasterPos4s (GLshort x, GLshort y, GLshort z, GLshort w);
void glRasterPos4sv (const GLshort *v);
void glReadBuffer (GLenum mode);
void glReadPixels (GLint x, GLint y, GLsizei width, GLsizei height, GLenum format, GLenum type, GLvoid *pixels);
void glRectd (GLdouble x1, GLdouble y1, GLdouble x2, GLdouble y2);
void glRectdv (const GLdouble *v1, const GLdouble *v2);
void glRectf (GLfloat x1, GLfloat y1, GLfloat x2, GLfloat y2);
void glRectfv (const GLfloat *v1, const GLfloat *v2);
void glRecti (GLint x1, GLint y1, GLint x2, GLint y2);
void glRectiv (const GLint *v1, const GLint *v2);
void glRects (GLshort x1, GLshort y1, GLshort x2, GLshort y2);
void glRectsv (const GLshort *v1, const GLshort *v2);
GLint glRenderMode (GLenum mode);
void glResetHistogram (GLenum target);
void glResetMinmax (GLenum target);
void glRotated (GLdouble angle, GLdouble x, GLdouble y, GLdouble z);
void glRotatef (GLfloat angle, GLfloat x, GLfloat y, GLfloat z);
void glScaled (GLdouble x, GLdouble y, GLdouble z);
void glScalef (GLfloat x, GLfloat y, GLfloat z);
void glScissor (GLint x, GLint y, GLsizei width, GLsizei height);
void glSelectBuffer (GLsizei size, GLuint *buffer);
void glSeparableFilter2D (GLenum target, GLenum internalformat, GLsizei width, GLsizei height, GLenum format, GLenum type, const GLvoid *row, const GLvoid *column);
void glShadeModel (GLenum mode);
void glStencilFunc (GLenum func, GLint ref, GLuint mask);
void glStencilMask (GLuint mask);
void glStencilOp (GLenum fail, GLenum zfail, GLenum zpass);
void glTexCoord1d (GLdouble s);
void glTexCoord1dv (const GLdouble *v);
void glTexCoord1f (GLfloat s);
void glTexCoord1fv (const GLfloat *v);
void glTexCoord1i (GLint s);
void glTexCoord1iv (const GLint *v);
void glTexCoord1s (GLshort s);
void glTexCoord1sv (const GLshort *v);
void glTexCoord2d (GLdouble s, GLdouble t);
void glTexCoord2dv (const GLdouble *v);
void glTexCoord2f (GLfloat s, GLfloat t);
void glTexCoord2fv (const GLfloat *v);
void glTexCoord2i (GLint s, GLint t);
void glTexCoord2iv (const GLint *v);
void glTexCoord2s (GLshort s, GLshort t);
void glTexCoord2sv (const GLshort *v);
void glTexCoord3d (GLdouble s, GLdouble t, GLdouble r);
void glTexCoord3dv (const GLdouble *v);
void glTexCoord3f (GLfloat s, GLfloat t, GLfloat r);
void glTexCoord3fv (const GLfloat *v);
void glTexCoord3i (GLint s, GLint t, GLint r);
void glTexCoord3iv (const GLint *v);
void glTexCoord3s (GLshort s, GLshort t, GLshort r);
void glTexCoord3sv (const GLshort *v);
void glTexCoord4d (GLdouble s, GLdouble t, GLdouble r, GLdouble q);
void glTexCoord4dv (const GLdouble *v);
void glTexCoord4f (GLfloat s, GLfloat t, GLfloat r, GLfloat q);
void glTexCoord4fv (const GLfloat *v);
void glTexCoord4i (GLint s, GLint t, GLint r, GLint q);
void glTexCoord4iv (const GLint *v);
void glTexCoord4s (GLshort s, GLshort t, GLshort r, GLshort q);
void glTexCoord4sv (const GLshort *v);
void glTexCoordPointer (GLint size, GLenum type, GLsizei stride, const GLvoid *pointer);
void glTexEnvf (GLenum target, GLenum pname, GLfloat param);
void glTexEnvfv (GLenum target, GLenum pname, const GLfloat *params);
void glTexEnvi (GLenum target, GLenum pname, GLint param);
void glTexEnviv (GLenum target, GLenum pname, const GLint *params);
void glTexGend (GLenum coord, GLenum pname, GLdouble param);
void glTexGendv (GLenum coord, GLenum pname, const GLdouble *params);
void glTexGenf (GLenum coord, GLenum pname, GLfloat param);
void glTexGenfv (GLenum coord, GLenum pname, const GLfloat *params);
void glTexGeni (GLenum coord, GLenum pname, GLint param);
void glTexGeniv (GLenum coord, GLenum pname, const GLint *params);
void glTexImage1D (GLenum target, GLint level, GLenum internalformat, GLsizei width, GLint border, GLenum format, GLenum type, const GLvoid *pixels);
void glTexImage2D (GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLint border, GLenum format, GLenum type, const GLvoid *pixels);
void glTexImage3D (GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLenum format, GLenum type, const GLvoid *pixels);
void glTexParameterf (GLenum target, GLenum pname, GLfloat param);
void glTexParameterfv (GLenum target, GLenum pname, const GLfloat *params);
void glTexParameteri (GLenum target, GLenum pname, GLint param);
void glTexParameteriv (GLenum target, GLenum pname, const GLint *params);
void glTexSubImage1D (GLenum target, GLint level, GLint xoffset, GLsizei width, GLenum format, GLenum type, const GLvoid *pixels);
void glTexSubImage2D (GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLenum type, const GLvoid *pixels);
void glTexSubImage3D (GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLenum type, const GLvoid *pixels);
void glTranslated (GLdouble x, GLdouble y, GLdouble z);
void glTranslatef (GLfloat x, GLfloat y, GLfloat z);
void glVertex2d (GLdouble x, GLdouble y);
void glVertex2dv (const GLdouble *v);
void glVertex2f (GLfloat x, GLfloat y);
void glVertex2fv (const GLfloat *v);
void glVertex2i (GLint x, GLint y);
void glVertex2iv (const GLint *v);
void glVertex2s (GLshort x, GLshort y);
void glVertex2sv (const GLshort *v);
void glVertex3d (GLdouble x, GLdouble y, GLdouble z);
void glVertex3dv (const GLdouble *v);
void glVertex3f (GLfloat x, GLfloat y, GLfloat z);
void glVertex3fv (const GLfloat *v);
void glVertex3i (GLint x, GLint y, GLint z);
void glVertex3iv (const GLint *v);
void glVertex3s (GLshort x, GLshort y, GLshort z);
void glVertex3sv (const GLshort *v);
void glVertex4d (GLdouble x, GLdouble y, GLdouble z, GLdouble w);
void glVertex4dv (const GLdouble *v);
void glVertex4f (GLfloat x, GLfloat y, GLfloat z, GLfloat w);
void glVertex4fv (const GLfloat *v);
void glVertex4i (GLint x, GLint y, GLint z, GLint w);
void glVertex4iv (const GLint *v);
void glVertex4s (GLshort x, GLshort y, GLshort z, GLshort w);
void glVertex4sv (const GLshort *v);
void glVertexPointer (GLint size, GLenum type, GLsizei stride, const GLvoid *pointer);
void glViewport (GLint x, GLint y, GLsizei width, GLsizei height);
void glSampleCoverage (GLclampf value, GLboolean invert);
void glSamplePass (GLenum pass);
void glLoadTransposeMatrixf (const GLfloat *m);
void glLoadTransposeMatrixd (const GLdouble *m);
void glMultTransposeMatrixf (const GLfloat *m);
void glMultTransposeMatrixd (const GLdouble *m);
void glCompressedTexImage3D (GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLsizei depth, GLint border, GLsizei imageSize, const GLvoid *data);
void glCompressedTexImage2D (GLenum target, GLint level, GLenum internalformat, GLsizei width, GLsizei height, GLint border, GLsizei imageSize, const GLvoid *data);
void glCompressedTexImage1D (GLenum target, GLint level, GLenum internalformat, GLsizei width, GLint border, GLsizei imageSize, const GLvoid *data);
void glCompressedTexSubImage3D (GLenum target, GLint level, GLint xoffset, GLint yoffset, GLint zoffset, GLsizei width, GLsizei height, GLsizei depth, GLenum format, GLsizei imageSize, const GLvoid *data);
void glCompressedTexSubImage2D (GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width, GLsizei height, GLenum format, GLsizei imageSize, const GLvoid *data);
void glCompressedTexSubImage1D (GLenum target, GLint level, GLint xoffset, GLsizei width, GLenum format, GLsizei imageSize, const GLvoid *data);
void glGetCompressedTexImage (GLenum target, GLint lod, GLvoid *img);
void glActiveTexture (GLenum texture);
void glClientActiveTexture (GLenum texture);
void glMultiTexCoord1d (GLenum target, GLdouble s);
void glMultiTexCoord1dv (GLenum target, const GLdouble *v);
void glMultiTexCoord1f (GLenum target, GLfloat s);
void glMultiTexCoord1fv (GLenum target, const GLfloat *v);
void glMultiTexCoord1i (GLenum target, GLint s);
void glMultiTexCoord1iv (GLenum target, const GLint *v);
void glMultiTexCoord1s (GLenum target, GLshort s);
void glMultiTexCoord1sv (GLenum target, const GLshort *v);
void glMultiTexCoord2d (GLenum target, GLdouble s, GLdouble t);
void glMultiTexCoord2dv (GLenum target, const GLdouble *v);
void glMultiTexCoord2f (GLenum target, GLfloat s, GLfloat t);
void glMultiTexCoord2fv (GLenum target, const GLfloat *v);
void glMultiTexCoord2i (GLenum target, GLint s, GLint t);
void glMultiTexCoord2iv (GLenum target, const GLint *v);
void glMultiTexCoord2s (GLenum target, GLshort s, GLshort t);
void glMultiTexCoord2sv (GLenum target, const GLshort *v);
void glMultiTexCoord3d (GLenum target, GLdouble s, GLdouble t, GLdouble r);
void glMultiTexCoord3dv (GLenum target, const GLdouble *v);
void glMultiTexCoord3f (GLenum target, GLfloat s, GLfloat t, GLfloat r);
void glMultiTexCoord3fv (GLenum target, const GLfloat *v);
void glMultiTexCoord3i (GLenum target, GLint s, GLint t, GLint r);
void glMultiTexCoord3iv (GLenum target, const GLint *v);
void glMultiTexCoord3s (GLenum target, GLshort s, GLshort t, GLshort r);
void glMultiTexCoord3sv (GLenum target, const GLshort *v);
void glMultiTexCoord4d (GLenum target, GLdouble s, GLdouble t, GLdouble r, GLdouble q);
void glMultiTexCoord4dv (GLenum target, const GLdouble *v);
void glMultiTexCoord4f (GLenum target, GLfloat s, GLfloat t, GLfloat r, GLfloat q);
void glMultiTexCoord4fv (GLenum target, const GLfloat *v);
void glMultiTexCoord4i (GLenum target, GLint, GLint s, GLint t, GLint r);
void glMultiTexCoord4iv (GLenum target, const GLint *v);
void glMultiTexCoord4s (GLenum target, GLshort s, GLshort t, GLshort r, GLshort q);
void glMultiTexCoord4sv (GLenum target, const GLshort *v);
void glFogCoordf (GLfloat coord);
void glFogCoordfv (const GLfloat *coord);
void glFogCoordd (GLdouble coord);
void glFogCoorddv (const GLdouble * coord);
void glFogCoordPointer (GLenum type, GLsizei stride, const GLvoid *pointer);
void glSecondaryColor3b (GLbyte red, GLbyte green, GLbyte blue);
void glSecondaryColor3bv (const GLbyte *v);
void glSecondaryColor3d (GLdouble red, GLdouble green, GLdouble blue);
void glSecondaryColor3dv (const GLdouble *v);
void glSecondaryColor3f (GLfloat red, GLfloat green, GLfloat blue);
void glSecondaryColor3fv (const GLfloat *v);
void glSecondaryColor3i (GLint red, GLint green, GLint blue);
void glSecondaryColor3iv (const GLint *v);
void glSecondaryColor3s (GLshort red, GLshort green, GLshort blue);
void glSecondaryColor3sv (const GLshort *v);
void glSecondaryColor3ub (GLubyte red, GLubyte green, GLubyte blue);
void glSecondaryColor3ubv (const GLubyte *v);
void glSecondaryColor3ui (GLuint red, GLuint green, GLuint blue);
void glSecondaryColor3uiv (const GLuint *v);
void glSecondaryColor3us (GLushort red, GLushort green, GLushort blue);
void glSecondaryColor3usv (const GLushort *v);
void glSecondaryColorPointer (GLint size, GLenum type, GLsizei stride, const GLvoid *pointer);
void glPointParameterf (GLenum pname, GLfloat param);
void glPointParameterfv (GLenum pname, const GLfloat *params);
void glPointParameteri (GLenum pname, GLint param);
void glPointParameteriv (GLenum pname, const GLint *params);
void glBlendFuncSeparate (GLenum srcRGB, GLenum dstRGB, GLenum srcAlpha, GLenum dstAlpha);
void glMultiDrawArrays (GLenum mode, const GLint *first, const GLsizei *count, GLsizei primcount);
void glMultiDrawElements (GLenum mode, const GLsizei *count, GLenum type, const GLvoid* *indices, GLsizei primcount);
void glWindowPos2d (GLdouble x, GLdouble y);
void glWindowPos2dv (const GLdouble *v);
void glWindowPos2f (GLfloat x, GLfloat y);
void glWindowPos2fv (const GLfloat *v);
void glWindowPos2i (GLint x, GLint y);
void glWindowPos2iv (const GLint *v);
void glWindowPos2s (GLshort x, GLshort y);
void glWindowPos2sv (const GLshort *v);
void glWindowPos3d (GLdouble x, GLdouble y, GLdouble z);
void glWindowPos3dv (const GLdouble *v);
void glWindowPos3f (GLfloat x, GLfloat y, GLfloat z);
void glWindowPos3fv (const GLfloat *v);
void glWindowPos3i (GLint x, GLint y, GLint z);
void glWindowPos3iv (const GLint *v);
void glWindowPos3s (GLshort x, GLshort y, GLshort z);
void glWindowPos3sv (const GLshort *v);
void glGenQueries(GLsizei n, GLuint *ids);
void glDeleteQueries(GLsizei n, const GLuint *ids);
GLboolean glIsQuery(GLuint id);
void glBeginQuery(GLenum target, GLuint id);
void glEndQuery(GLenum target);
void glGetQueryiv(GLenum target, GLenum pname, GLint *params);
void glGetQueryObjectiv(GLuint id, GLenum pname, GLint *params);
void glGetQueryObjectuiv(GLuint id, GLenum pname, GLuint *params);
void glBindBuffer (GLenum target, GLuint buffer);
void glDeleteBuffers (GLsizei n, const GLuint *buffers);
void glGenBuffers (GLsizei n, GLuint *buffers);
GLboolean glIsBuffer (GLuint buffer);
void glBufferData (GLenum target, GLsizeiptr size, const GLvoid *data, GLenum usage);
void glBufferSubData (GLenum target, GLintptr offset, GLsizeiptr size, const GLvoid *data);
void glGetBufferSubData (GLenum target, GLintptr offset, GLsizeiptr size, GLvoid *data);
GLvoid * glMapBuffer (GLenum target, GLenum access);
GLboolean glUnmapBuffer (GLenum target);
void glGetBufferParameteriv (GLenum target, GLenum pname, GLint *params);
void glGetBufferPointerv (GLenum target, GLenum pname, GLvoid **params);
void glDrawBuffers (GLsizei n, const GLenum *bufs);
void glVertexAttrib1d (GLuint index, GLdouble x);
void glVertexAttrib1dv (GLuint index, const GLdouble *v);
void glVertexAttrib1f (GLuint index, GLfloat x);
void glVertexAttrib1fv (GLuint index, const GLfloat *v);
void glVertexAttrib1s (GLuint index, GLshort x);
void glVertexAttrib1sv (GLuint index, const GLshort *v);
void glVertexAttrib2d (GLuint index, GLdouble x, GLdouble y);
void glVertexAttrib2dv (GLuint index, const GLdouble *v);
void glVertexAttrib2f (GLuint index, GLfloat x, GLfloat y);
void glVertexAttrib2fv (GLuint index, const GLfloat *v);
void glVertexAttrib2s (GLuint index, GLshort x, GLshort y);
void glVertexAttrib2sv (GLuint index, const GLshort *v);
void glVertexAttrib3d (GLuint index, GLdouble x, GLdouble y, GLdouble z);
void glVertexAttrib3dv (GLuint index, const GLdouble *v);
void glVertexAttrib3f (GLuint index, GLfloat x, GLfloat y, GLfloat z);
void glVertexAttrib3fv (GLuint index, const GLfloat *v);
void glVertexAttrib3s (GLuint index, GLshort x, GLshort y, GLshort z);
void glVertexAttrib3sv (GLuint index, const GLshort *v);
void glVertexAttrib4Nbv (GLuint index, const GLbyte *v);
void glVertexAttrib4Niv (GLuint index, const GLint *v);
void glVertexAttrib4Nsv (GLuint index, const GLshort *v);
void glVertexAttrib4Nub (GLuint index, GLubyte x, GLubyte y, GLubyte z, GLubyte w);
void glVertexAttrib4Nubv (GLuint index, const GLubyte *v);
void glVertexAttrib4Nuiv (GLuint index, const GLuint *v);
void glVertexAttrib4Nusv (GLuint index, const GLushort *v);
void glVertexAttrib4bv (GLuint index, const GLbyte *v);
void glVertexAttrib4d (GLuint index, GLdouble x, GLdouble y, GLdouble z, GLdouble w);
void glVertexAttrib4dv (GLuint index, const GLdouble *v);
void glVertexAttrib4f (GLuint index, GLfloat x, GLfloat y, GLfloat z, GLfloat w);
void glVertexAttrib4fv (GLuint index, const GLfloat *v);
void glVertexAttrib4iv (GLuint index, const GLint *v);
void glVertexAttrib4s (GLuint index, GLshort x, GLshort y, GLshort z, GLshort w);
void glVertexAttrib4sv (GLuint index, const GLshort *v);
void glVertexAttrib4ubv (GLuint index, const GLubyte *v);
void glVertexAttrib4uiv (GLuint index, const GLuint *v);
void glVertexAttrib4usv (GLuint index, const GLushort *v);
void glVertexAttribPointer (GLuint index, GLint size, GLenum type, GLboolean normalized, GLsizei stride, const GLvoid *pointer);
void glEnableVertexAttribArray (GLuint index);
void glDisableVertexAttribArray (GLuint index);
void glGetVertexAttribdv (GLuint index, GLenum pname, GLdouble *params);
void glGetVertexAttribfv (GLuint index, GLenum pname, GLfloat *params);
void glGetVertexAttribiv (GLuint index, GLenum pname, GLint *params);
void glGetVertexAttribPointerv (GLuint index, GLenum pname, GLvoid* *pointer);
void glDeleteShader (GLuint shader);
void glDetachShader (GLuint program, GLuint shader);
GLuint glCreateShader (GLenum type);
void glShaderSource (GLuint shader, GLsizei count, const GLchar* *string, const GLint *length);
void glCompileShader (GLuint shader);
GLuint glCreateProgram (void);
void glAttachShader (GLuint program, GLuint shader);
void glLinkProgram (GLuint program);
void glUseProgram (GLuint program);
void glDeleteProgram (GLuint program);
void glValidateProgram (GLuint program);
void glUniform1f (GLint location, GLfloat v0);
void glUniform2f (GLint location, GLfloat v0, GLfloat v1);
void glUniform3f (GLint location, GLfloat v0, GLfloat v1, GLfloat v2);
void glUniform4f (GLint location, GLfloat v0, GLfloat v1, GLfloat v2, GLfloat v3);
void glUniform1i (GLint location, GLint v0);
void glUniform2i (GLint location, GLint v0, GLint v1);
void glUniform3i (GLint location, GLint v0, GLint v1, GLint v2);
void glUniform4i (GLint location, GLint v0, GLint v1, GLint v2, GLint v3);
void glUniform1fv (GLint location, GLsizei count, const GLfloat *value);
void glUniform2fv (GLint location, GLsizei count, const GLfloat *value);
void glUniform3fv (GLint location, GLsizei count, const GLfloat *value);
void glUniform4fv (GLint location, GLsizei count, const GLfloat *value);
void glUniform1iv (GLint location, GLsizei count, const GLint *value);
void glUniform2iv (GLint location, GLsizei count, const GLint *value);
void glUniform3iv (GLint location, GLsizei count, const GLint *value);
void glUniform4iv (GLint location, GLsizei count, const GLint *value);
void glUniformMatrix2fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix3fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix4fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
GLboolean glIsShader (GLuint shader);
GLboolean glIsProgram (GLuint program);
void glGetShaderiv (GLuint shader, GLenum pname, GLint *params);
void glGetProgramiv (GLuint program, GLenum pname, GLint *params);
void glGetAttachedShaders (GLuint program, GLsizei maxCount, GLsizei *count, GLuint *shaders);
void glGetShaderInfoLog (GLuint shader, GLsizei bufSize, GLsizei *length, GLchar *infoLog);
void glGetProgramInfoLog (GLuint program, GLsizei bufSize, GLsizei *length, GLchar *infoLog);
GLint glGetUniformLocation (GLuint program, const GLchar *name);
void glGetActiveUniform (GLuint program, GLuint index, GLsizei bufSize, GLsizei *length, GLint *size, GLenum *type, GLchar *name);
void glGetUniformfv (GLuint program, GLint location, GLfloat *params);
void glGetUniformiv (GLuint program, GLint location, GLint *params);
void glGetShaderSource (GLuint shader, GLsizei bufSize, GLsizei *length, GLchar *source);
void glBindAttribLocation (GLuint program, GLuint index, const GLchar *name);
void glGetActiveAttrib (GLuint program, GLuint index, GLsizei bufSize, GLsizei *length, GLint *size, GLenum *type, GLchar *name);
GLint glGetAttribLocation (GLuint program, const GLchar *name);
void glStencilFuncSeparate (GLenum face, GLenum func, GLint ref, GLuint mask);
void glStencilOpSeparate (GLenum face, GLenum fail, GLenum zfail, GLenum zpass);
void glStencilMaskSeparate (GLenum face, GLuint mask);
void glUniformMatrix2x3fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix3x2fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix2x4fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix4x2fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix3x4fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
void glUniformMatrix4x3fv (GLint location, GLsizei count, GLboolean transpose, const GLfloat *value);
]]

local library = {
   ["OSX"]     = "OpenGL.framework/OpenGL",
   ["Windows"] = "OPENGL32.DLL",
   ["Linux"]   = "libGL.so",
   ["BSD"]     = "libGL.so",
   ["POSIX"]   = "libGL.so",
   ["Other"]   = "libGL.so",
}
return ffi.load( library[ ffi.os ] )

-- )EOF"
