//--------------------------------------------------------------------------
// File: main.c
// Author: George Bain
// Date: July 10, 1998
// Description: Chapter 2: Graphic Example 9 - Move, Scale, and Rotate Sprites
// Copyright (C) 1998 Sony Computer Entertainment Europe.,
//           All Rights Reserved.  Permission granted to whom ever.
//--------------------------------------------------------------------------

// This full demo (and many others) is available here:
// https://github.com/gwald/netyaroze_demo/tree/main/tutor/chap2/9

// For Net Yaroze help read: MyProject/third_party/net-yaroze/help.html 

//--------------------------------------------------------------------------
// I N C L U D E S
//--------------------------------------------------------------------------

#include <libps.h>
#include <stdio.h>
#include "main.h" // Prototypes and controller stuff

/* 
	Embedded data isn't required with Net Yaroze but used here for simplisity.
	Normally data is loaded via a Siocons script into RAM locations and packaged as a sinle executable with yarexe. 

*/
#include "image.h" // contains yar8bit.tim as a char array.
	
//--------------------------------------------------------------------------
// D E F I N E S 
//-------------------------------------------------------------------------- 

// texture
#define TIM_ADDR yar8bit_tim //(0x80090000)

//--------------------------------------------------------------------------
// G L O B A L S
//--------------------------------------------------------------------------

int output_buffer_index;            // buffer index
GsOT world_ordering_table[2];       // ordering table headers
GsOT_TAG ordering_table[2][1<<1];   // actual ordering tables
PACKET gpu_work_area[2][24000];     // GPU packet work area
u_char prev_mode;					// previous code
int fnt_id[9];						// font id
RECT rect;							// TIM rect
GsIMAGE tim;						// TIM image
GsSPRITE sprite;					// our sprite

//--------------------------------------------------------------------------
// Function: main()
// Description: Graphic Example 9 - Move, Scale, and Rotate Sprites
// Parameters: none
// Returns: int
// Notes: N/A
//--------------------------------------------------------------------------

int main( void )
 {	            

   	InitGame();  
   	 
	ReadTIM( (u_long *)TIM_ADDR );

	InitSprite();     

	// main loop
    while( !DONE )
      {
		 	     
		 FntPrint(fnt_id[0], (char*)"~c900 Graphic Example 9 - Move, Scale, and Rotate Sprites ");
		 
         if( PAD_PRESS(buffer1,PAD_LEFT) )
		   {
			sprite.x -=5;

		   }
		 if( PAD_PRESS(buffer1,PAD_RIGHT) )
		   {
			sprite.x +=5;

		   }
		 if( PAD_PRESS(buffer1,PAD_UP) )
		   {
			sprite.y -=5;

		   }
		 if( PAD_PRESS(buffer1,PAD_DOWN) )
		   {
			sprite.y +=5;

		   }
		 if( PAD_PRESS(buffer1,PAD_SQUARE) )
		   {
			 sprite.scalex -= 20; 
		   }
		 if( PAD_PRESS(buffer1,PAD_CIRCLE) )
		   {
			 sprite.scalex += 20; 
		   }

         if( PAD_PRESS(buffer1,PAD_TRIANGLE) )
		   {
			 sprite.scaley -= 20; 
		   }
		 if( PAD_PRESS(buffer1,PAD_CROSS) )
		   {
			 sprite.scaley += 20; 
		   }
		   
		 if( PAD_PRESS(buffer1,PAD_L1) )
		   {
			 sprite.rotate -= ONE;
		   }

	   	 if( PAD_PRESS(buffer1,PAD_R1) )
		   {
			 sprite.rotate += ONE;
		   }

	   	 UpdateScreen();

      }// end while loop

    DeInitGame();   // de-init the game
	

    return(0);      // success

 }// end main 





//--------------------------------------------------------------------------
// Function: InitSprite()
// Description: Setup sprite structure
// Parameters: none
// Returns: none
// Notes: N/A
//--------------------------------------------------------------------------

void InitSprite( void )
 {

	sprite.attribute |= (1<<24);   // 8-bit sprite
	
	sprite.x = 0;
	sprite.y = 50;

	sprite.w = (tim.pw*2);  // (width*2) = rendered 8bit width
	sprite.h = tim.ph;

	sprite.tpage = GetTPage(1,0,tim.px,tim.py);

	sprite.u = 0;
	sprite.v = 0;

	sprite.cx = tim.cx;
	sprite.cy = tim.cy;;

	sprite.r = 0x80;
	sprite.g = 0x80;
	sprite.b = 0x80;

	sprite.mx = (tim.pw*2) /2;
	sprite.my = (tim.ph/2);

	sprite.scalex = ONE;
	sprite.scaley = ONE;
	sprite.rotate = 0;


 }// end InitSprite





//--------------------------------------------------------------------------
// Function: ReadTIM()
// Description: Setup sprite structure
// Parameters: none
// Returns: none
// Notes: Look at Library Reference Manual
//--------------------------------------------------------------------------

void ReadTIM( u_long *addr )
 { 	
   
	// skip id and initialize image structure 
	addr ++;
	GsGetTimInfo(addr, &tim);
	DrawSync(0);
			
	// transfer pixel data to VRAM 
	rect.x = tim.px;
	rect.y = tim.py;
	rect.w = tim.pw;
	rect.h = tim.ph;
	LoadImage(&rect, tim.pixel);
	DrawSync(0);
			
    // if CLUT exists, transfer it to VRAM 
 	if( (tim.pmode >> 3) & 0x01 ) 
 	  {
 	  	rect.x = tim.cx;
	  	rect.y = tim.cy;
	  	rect.w = tim.cw;
	  	rect.h = tim.ch;
	  	LoadImage(&rect, tim.clut);
	  }	 
  
   DrawSync(0);

   printf(" IMAGE - x:(%d), y:(%d), w:(%d), h:(%d) \n", tim.px, tim.py,tim.pw,tim.ph );
   printf(" CLUT - x:(%d), y:(%d), w:(%d), h:(%d) \n", tim.cx, tim.cy,tim.cw,tim.ch );
   printf(" image mode:%d \n", tim.pmode);
   
}// end ReadTIM 

 



//--------------------------------------------------------------------------
// Function: InitGame()
// Description: Initialise the graphics mode, joypad, ordering tables,
//              textures, and objects
// Parameters: none
// Returns: void
// Notes: N/A
//--------------------------------------------------------------------------

void InitGame( void )
 {

	 int count;
     
	 printf("Starting InitGame() \n");
	
  
	 // all reset, the drawing environment and display are initialised
	 ResetGraph(0);

	//This function MUST be called before using other libGS functions!
	 GsInitGraph( SCREEN_WIDTH, SCREEN_HEIGHT,
			      GsOFSGPU|GsINTER, 0, 0 );


	 // load in the font pattern
	 FntLoad(960,256);
     printf("Fonts loaded: \n");

	 fnt_id[0] = FntOpen(0,10,SCREEN_WIDTH, SCREEN_HEIGHT,0,80);
	 fnt_id[1] = FntOpen(0,20,SCREEN_WIDTH, SCREEN_HEIGHT,0,80);
	 fnt_id[2] = FntOpen(0,30,SCREEN_WIDTH, SCREEN_HEIGHT,0,80);
	 fnt_id[3] = FntOpen(0,40,SCREEN_WIDTH, SCREEN_HEIGHT,0,80);

	 fnt_id[4] = FntOpen(0,120,SCREEN_WIDTH, SCREEN_HEIGHT,0,80);
	 fnt_id[5] = FntOpen(0,130,SCREEN_WIDTH, SCREEN_HEIGHT,0,80);
	 fnt_id[6] = FntOpen(0,140,SCREEN_WIDTH, SCREEN_HEIGHT,0,80);
	 fnt_id[7] = FntOpen(0,150,SCREEN_WIDTH, SCREEN_HEIGHT,0,80);
	  
   	 // save current video mode
	 prev_mode = GetVideoMode();

	 // init graphic mode
	 SetVideoMode( MODE_PAL );
	 printf("Set video mode complete: \n");

	 // init the controller buffers
	 GetPadBuf((volatile unsigned char **)&buffer1,(volatile unsigned char **)&buffer2); 
	 printf("Set controller buffers complete: \n");

	 printf("Screen size setup complete: \n");

	 // double buffer definition
	 GsDefDispBuff( 0, 0, 0, 0 );
	 printf("Double buffer setup complete: \n");

	 
	 // set display output on t.v 
	 GsDISPENV.screen.x = 10;
	 GsDISPENV.screen.y = 18;
	 GsDISPENV.screen.w = 255;
	 GsDISPENV.screen.h = 255; 
	 
	 // set bg clear color and flag
  	 GsDRAWENV.r0 = 0x00;
	 GsDRAWENV.g0 = 0x00;
	 GsDRAWENV.b0 = 0x80;
	 GsDRAWENV.isbg = 1;	  	
  	
	 // set up the ordering table handlers
	 for( count=0; count < 2; count++ )
	    {
		  world_ordering_table[count].length = 1;
		  world_ordering_table[count].org = ordering_table[count];
	    }

	 // initialises the ordering table
	 GsClearOt( 0, 0, &world_ordering_table[output_buffer_index]);
	 GsClearOt( 0, 0, &world_ordering_table[output_buffer_index+1]);
	 printf("WOT is setup and complete: \n");
     printf("Game setup is complete: \n");

 }// end InitGame





//--------------------------------------------------------------------------
// Function: DeInitGame()
// Description: De-init the game, sound, graphics, etc
// Parameters: none
// Returns: void
// Notes: N/A
//--------------------------------------------------------------------------

void DeInitGame( void )
 {

 	 // set previous video mode
	 SetVideoMode( prev_mode );

	 // current drawing is canvelled and the command queue is flushed
	 ResetGraph(3);	   

	 printf("Graphics flushed: \n");
	 printf("Game now de-int: \n");
 
 }// end DeInitGame





//------------------------------------------------------------------------------
// Function: UpdateScreen()
// Description: Updates all the game objects and redraws the screen
// Parameters: none
// Returns: void
// Notes: Notice that DrawSync() and GsSortClear() are not being called.
//
//        There is no need to call DrawSync() since we are in interlace
//        mode and do not want to wait for drawing to be completed. 
// 
//        There is no need to call GsSortClear() since we are setting
//        GsDRAWENV.isbg = 1; 
//------------------------------------------------------------------------------

void UpdateScreen( void )
 {

	int count;

	// get the active buffer
    output_buffer_index = GsGetActiveBuff();

    // sets drawing command storage address
    GsSetWorkBase((PACKET*)gpu_work_area[output_buffer_index]);

    // initialises the ordering table
    GsClearOt(0, 0, &world_ordering_table[output_buffer_index]);

    // rendering done here
    
	for( count =0; count <8; count++ )
         FntFlush(fnt_id[count]);         
         
    GsSortSprite(&sprite, &world_ordering_table[output_buffer_index], 0);           
		
    // wait for vertical synchronisation
    VSync(0);    // 0: blocking until vertical synch occurs

    // swap double buffers, (changes the display buffer and drawing buffer)
    GsSwapDispBuff(); 
       
	// start execution of the drawing command registered in OT
    GsDrawOt(&world_ordering_table[output_buffer_index]);

 }// end UpdateScreen 




//----------------------------------EOF-------------------------------------
