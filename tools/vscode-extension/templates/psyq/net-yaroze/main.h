//--------------------------------------------------------------------------
// File: main.h
// Author: George Bain
// Date: July 10, 1998
// Description: Prototypes
// Copyright (C) 1998 Sony Computer Entertainment Europe.,
//           All Rights Reserved.  Permission granted to whom ever.
//-------------------------------------------------------------------------- 

#ifndef _MAIN_H
#define _MAIN_H

//--------------------------------------------------------------------------
// D E F I N E S 
//-------------------------------------------------------------------------- 

// screen resolution
#define SCREEN_WIDTH  640
#define SCREEN_HEIGHT 512

//--------------------------------------------------------------------------
// G L O B A L S
//--------------------------------------------------------------------------

extern int output_buffer_index;            // buffer index
extern GsOT world_ordering_table[2];       // ordering table headers
extern GsOT_TAG ordering_table[2][1<<1];   // actual ordering tables
extern PACKET gpu_work_area[2][24000];     // GPU packet work area
extern u_char prev_mode;				   // previous code
extern int fnt_id[9]; 

//--------------------------------------------------------------------------
// P R O T O T Y P E S
//--------------------------------------------------------------------------

void ReadTIM( u_long *addr );
void InitGame( void );
void DeInitGame( void );
void UpdateScreen( void );
void InitSprite( void );


//--------------------------------------------------------------------------
// File: cntrl.h
// Author: George Bain
// Date: June 17, 1998
// Description: Controller type macros and defines.
// Copyright (C) 1998 Sony Computer Entertainment Europe.,
//           All Rights Reserved.  Permission granted to whom ever.
//-------------------------------------------------------------------------- 


//--------------------------------------------------------------------------
// D E F I N E S 
//--------------------------------------------------------------------------

// quit macro
#define DONE (PAD_PRESS(buffer1,PAD_SELECT) && PAD_PRESS(buffer1,PAD_START))

// terminal types
#define MOUSE 		  (0x1)
#define NEGCON		  (0x2)
#define NORMAL 		  (0x4)
#define ANALOG_JOY    (0x5)
#define GUNCON        (0x6)
#define ANALOG        (0x7)

// mouse defines
#define MOUSE_RIGHT  (1<<2)	 
#define MOUSE_LEFT   (1<<3)	 
#define MOUSE_NOKEY  (0xFC)

// controller defines 14 buttons, 16 when in analog mode
#define PAD_NOKEY     (0xFFFF)
#define PAD_BAD		  (0xFF)

#define PAD_LEFT	  (1<<7)
#define PAD_RIGHT	  (1<<5)
#define PAD_UP		  (1<<4)
#define PAD_DOWN	  (1<<6)

#define PAD_TRIANGLE  (1<<12)
#define PAD_CIRCLE	  (1<<13)
#define PAD_CROSS	  (1<<14)
#define PAD_SQUARE	  (1<<15)

#define PAD_SELECT	  (1<<0)
#define PAD_START	  (1<<3)

#define PAD_L1		  (1<<10)
#define PAD_L2		  (1<<8)
#define PAD_L3		  (1<<1)
#define PAD_R1		  (1<<11)
#define	PAD_R2		  (1<<9)
#define PAD_R3		  (1<<2)


// neGcon defines
#define NEGCON_LEFT	  (1<<7)
#define NEGCON_RIGHT  (1<<5)
#define NEGCON_DOWN	  (1<<6)
#define NEGCON_UP	  (1<<4)
#define NEGCON_A	  (1<<13)
#define NEGCON_B	  (1<<12)
#define NEGCON_START  (1<<3)
#define NEGCON_R	  (1<<11)

// Namco guncon defines
#define GUNCON_A	   (1<<3)
#define GUNCON_B	   (1<<14)
#define GUNCON_TRIGGER (1<<13)


// controller check macros
#define PAD_PRESS(x,y) (~(x)->data.pad & (y))

#define MOUSE_PRESS(x,y) (~(x)->data.mouse.buttons & (y)) 
#define MOUSE_X(x) ((x)->data.mouse.x_offset)
#define MOUSE_Y(x) ((x)->data.mouse.y_offset)

#define NEGCON_PRESS(x,y) (~(x)->data.negcon.buttons & (y))
#define NEGCON_PRESS_L(x) ((x)->data.negcon.button_L)
#define NEGCON_PRESS_I(x) ((x)->data.negcon.button_I)
#define NEGCON_PRESS_II(x) ((x)->data.negcon.button_II)
#define NEGCON_PRESS_TWIST(x) ((x)->data.negcon.twist) 

#define GUNCON_PRESS(x,y) (~(x)->data.guncon.buttons & (y))
#define GUNCON_X(x) ((x)->data.guncon.guncon_x)
#define GUNCON_Y(x) ((x)->data.guncon.guncon_y)
#define GUNCON_DIV(x) ((x)->data.guncon.guncon_screen_div)

#define ANALOG_LEFT_X(x)  ((x)->data.analog.left_x)
#define ANALOG_LEFT_Y(x)  ((x)->data.analog.left_y)
#define ANALOG_RIGHT_X(x) ((x)->data.analog.right_x)
#define ANALOG_RIGHT_Y(x) ((x)->data.analog.right_y)

//--------------------------------------------------------------------------
// S T R U C T U R E S
//--------------------------------------------------------------------------


typedef struct guncon_tag
 {
	// 2 bytes
	u_short buttons;   // button A, B, and TRIGGER
	  
 	u_short guncon_x;			// x offset
	u_short guncon_y;		    // y offset	
 	
 }guncon_data;


typedef struct mouse_tag
 { 
  
  char not_used;		   // not used

  char buttons;			   // 2nd bit: right, 3rd bit: left
  signed char x_offset;	   // movement in x direction: -128~127
  signed char y_offset;	   // movement in y direction: -128~127

 }mouse_data;

typedef struct negcon_tag
 { 
  
  u_short buttons;		   // LEFT, RIGHT, DOWN, UP, START, A, B, and R

  u_char twist;			   // the twist value
  u_char button_I; 		   // I button
  u_char button_II;		   // II button
  u_char button_L;		   // L button
  
 }negcon_data;

typedef struct analog_tag
 {

   u_short buttons;   	  // 16 buttons
   u_char right_x;		  // movement on right stick x direction: 0~255
   u_char right_y;		  // movement on right stick y direction: 0~255
   u_char left_x;		  // movement on left stick x direction: 0~255
   u_char left_y;		  // movement on left stick y direction: 0~255

 }analog_data;

typedef u_short pad_data; // 14 button controller
 

typedef struct packet_tag
 {
	// 0-7
	u_char status; // 0xff: no controller, 0x00 controller connected
	u_char type;   // upper 4 bits: terminal type
				   // lower 4 bits: size of data received / 2

	// 2-6 bytes of data
	// 2 bytes for 14 button controller	
	// add 4 bytes for analog, now total of 6 bytes of received data	

	union 
	 {
	   pad_data pad;
	   mouse_data mouse;
	   analog_data analog;
	   negcon_data negcon;
	   guncon_data guncon;
     }data;		

 }cntrl_data, *cntrl_ptr;

//--------------------------------------------------------------------------
// G L O B A L S 
//--------------------------------------------------------------------------

// 8 bytes for each buffer
cntrl_data *buffer1, *buffer2; 


#endif

//----------------------------------EOF-------------------------------------
