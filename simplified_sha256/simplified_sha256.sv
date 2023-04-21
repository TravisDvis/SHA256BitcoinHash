module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK1, COMPUTE1, BLOCK2, COMPUTE2, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[64];
logic [31:0] message[20];
logic [31:0] ha[8];
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i, j;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [512:0] memory_block[2];
logic [ 7:0] tstep;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


assign num_blocks = 2;//determine_num_blocks(NUM_OF_WORDS); 
assign tstep = (i - 1);


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    // Student to add remaning code below
    // Refer to SHA256 discussion slides to get logic for this function
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a,2) ^ rightrotate(a,13) ^ rightrotate(a,22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

function logic [31:0] word_expansion(input logic [31:0] w[64], logic[7:0] i);
    logic [31:0] s1, s0; // internal signals
begin

	s0 = rightrotate(w[i-15],7) ^ rightrotate(w[i-15],18) ^ (w[i-15] >> 3);
	s1 = rightrotate(w[i-2],17) ^ rightrotate(w[i-2],19) ^ (w[i-2] >> 10);
	word_expansion= w[i-16] + s0 + w[i-7] + s1;
	
end
endfunction

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x, input logic [ 7:0] r);
begin
   
	rightrotate = (x >> r) | (x << (32 - r));

end	
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin
       // Student to add rest of the code  

			ha[0] <= 32'h6a09e667;
			ha[1] <= 32'hbb67ae85;
			ha[2] <= 32'h3c6ef372;
			ha[3] <= 32'ha54ff53a;
			ha[4] <= 32'h510e527f;
			ha[5] <= 32'h9b05688c;
			ha[6] <= 32'h1f83d9ab;
			ha[7] <= 32'h5be0cd19;

			cur_we <= 1'b0;
			offset <= 0;
			cur_addr <= message_addr;
			cur_write_data <= 32'h0;

			state <= READ;

       end
    end

    READ: begin

		if (offset < 21) begin
		
			message[offset-1] <= mem_read_data;

			offset <= offset + 1;

			cur_we <= 1'b0;

			state <= READ;

		end

		else begin

			i <= 0;
			offset <= 0;
			state <= BLOCK1;
			cur_we <= 1'b1;

		end

	end

    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
    BLOCK1: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation 


		w[0] <= message[0];
		w[1] <= message[1];
		w[2] <= message[2];	
		w[3] <= message[3];
		w[4] <= message[4];
		w[5] <= message[5];
		w[6] <= message[6];
		w[7] <= message[7];
		w[8] <= message[8];
		w[9] <= message[9];
		w[10] <= message[10];
		w[11] <= message[11];
		w[12] <= message[12];
		w[13] <= message[13];
		w[14] <= message[14];
		w[15] <= message[15];
			
		ha[0] <= 32'h6a09e667;
		ha[1] <= 32'hbb67ae85;
		ha[2] <= 32'h3c6ef372;
		ha[3] <= 32'ha54ff53a;
		ha[4] <= 32'h510e527f;
		ha[5] <= 32'h9b05688c;
		ha[6] <= 32'h1f83d9ab;
		ha[7] <= 32'h5be0cd19;
		
		a <= 32'h6a09e667;
		b <= 32'hbb67ae85;
		c <= 32'h3c6ef372;
		d <= 32'ha54ff53a;
		e <= 32'h510e527f;
		f <= 32'h9b05688c;
		g <= 32'h1f83d9ab;
		h <= 32'h5be0cd19;
		
		i <= 0;
		state <= COMPUTE1;

    end


    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE1: begin
	// 64 processing rounds steps for 512-bit block 
		
		if(i<=64) begin

			if (i<16) begin
				
				{a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
				
				i <= i+1;
				state <= COMPUTE1;
				
			end
			
			else begin 
							
				w[i] <= word_expansion(w,i);		
				
				if(i!=16) begin
				
					{a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[tstep], tstep);
				
				end
				
				i <= i+1;
				state <= COMPUTE1;
				
			end
			
		end
		
		else begin			
			
			ha[0] <= ha[0] + a;
			ha[1] <= ha[1] + b;	
			ha[2] <= ha[2] + c;	
			ha[3] <= ha[3] + d;	
			ha[4] <= ha[4] + e;	
			ha[5] <= ha[5] + f;	
			ha[6] <= ha[6] + g;
			ha[7] <= ha[7] + h;
			
			i <= 0;
			state <= BLOCK2;	
			
		end
		
	end
	
	BLOCK2: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation 

		w[0] <= message[16];
		w[1] <= message[17];
		w[2] <= message[18];	
		w[3] <= message[19];
		w[4] <= 32'h80000000;
		w[5] <= 32'h00000000;
		w[6] <= 32'h00000000;
		w[7] <= 32'h00000000;
		w[8] <= 32'h00000000;
		w[9] <= 32'h00000000;
		w[10] <= 32'h00000000;
		w[11] <= 32'h00000000;
		w[12] <= 32'h00000000;
		w[13] <= 32'h00000000;
		w[14] <= 32'h00000000;
		w[15] <= 32'd640;
		
		a <= ha[0];
		b <= ha[1];
		c <= ha[2];
		d <= ha[3];
		e <= ha[4];
		f <= ha[5];
		g <= ha[6];
		h <= ha[7];
		
		i<=0;
		state <= COMPUTE2;

    end
	 
	 COMPUTE2: begin
		
		if (i<=64) begin
		
			if (i<16) begin
				
				{a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
				
				i <= i+1;
				state <= COMPUTE2;
				
			end
			
			else begin 
				
							
				w[i] <= word_expansion(w,i);
				
				
				if(i!=16) begin
				
					{a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[tstep], tstep);
				
				end
				
				i <= i+1;
				state <= COMPUTE2;
				
			end
			
		end
		
		else begin
			
			ha[0] <= ha[0] + a;
			ha[1] <= ha[1] + b;	
			ha[2] <= ha[2] + c;	
			ha[3] <= ha[3] + d;	
			ha[4] <= ha[4] + e;	
			ha[5] <= ha[5] + f;	
			ha[6] <= ha[6] + g;
			ha[7] <= ha[7] + h;
			
			offset <= 0;
			i <= 0;
			state <= WRITE;
			
		end
	
	end 
	
    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
	WRITE: begin
		
		if(i<8) begin
			
			cur_addr <= output_addr + i;
			cur_write_data <= ha[i];
			
			state <= WRITE;
			i <= i+1;
			cur_we <= 1'b1;
			
		end
			
		else begin
				
			state <= IDLE;
			i <= 0;
				
		end

	end
endcase
end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
