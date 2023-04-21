
module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter NUM_NONCES = 8;

// FSM state variables 
enum logic [3:0] {IDLE, READ, BLOCK1, COMPUTE1, FURTHERPROCESSING, BLOCK2, COMPUTE2, BLOCK3, COMPUTE3, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[16];
logic [31:0] wn[NUM_NONCES][16];
logic [31:0] message[19:0];
logic [ 7:0] i,j;
logic [ 1:0] pass;
logic [31:0] n;
logic [15:0] offset; // in word address
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [512:0] memory_block[2];
logic [ 7:0] tstep;

assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

assign tstep = (i-1);

// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w, input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
	S0 = rightrotate(a,2) ^ rightrotate(a,13) ^ rightrotate(a,22);
   maj = (a & b) ^ (a & c) ^ (b & c);
	t2 = S0 + maj;
	S1 = rightrotate(e,6) ^ rightrotate(e,11) ^ rightrotate(e,25);
	ch = (e & f) ^ ((~e) & g);
	t1 = h + S1 + ch + k[t] + w;
	sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

function logic [31:0] wtnew(input logic [31:0] w[16]);
	logic [31:0] s1, s0; // internal signals
begin

	s0 = rightrotate(w[1],7) ^ rightrotate(w[1],18) ^ (w[1] >> 3);
	s1 = rightrotate(w[14],17) ^ rightrotate(w[14],19) ^ (w[14] >> 10);
	wtnew = w[0] + s0 + w[9] + s1;
	
end
endfunction


function logic [31:0] word_expansion_multi(input logic [31:0] w[NUM_NONCES][64], input logic[31:0] n, input logic[7:0] i);
    logic [31:0] s1, s0; // internal signals
begin

	s0 = rightrotate(w[n][i-15],7) ^ rightrotate(w[n][i-15],18) ^ (w[n][i-15] >> 3);
	s1 = rightrotate(w[n][i-2],17) ^ rightrotate(w[n][i-2],19) ^ (w[n][i-2] >> 10);
	word_expansion_multi = w[n][i-16] + s0 + w[n][i-7] + s1;
	
end
endfunction


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,input logic [ 7:0] r);
begin 
	rightrotate = (x >> r) | (x << (32 - r));
end
endfunction
  
// Student to add rest of the code here

logic [31:0] ha[NUM_NONCES][8];

logic [31:0] fh0, fh1, fh2, fh3, fh4, fh5, fh6, fh7;

logic [31:0] a, b, c, d, e, f, g, h;

logic [31:0] an[NUM_NONCES], bn[NUM_NONCES], cn[NUM_NONCES], dn[NUM_NONCES], en[NUM_NONCES], fn[NUM_NONCES], gn[NUM_NONCES], hn[NUM_NONCES];

always_ff @(posedge clk, negedge reset_n) begin
	
	if (!reset_n) begin
		state <= IDLE;
		
	end
	else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
		IDLE: begin 
			if(start) begin
       // Student to add rest of the code  

				cur_we <= 1'b0;
				offset <= 0;
				cur_addr <= message_addr;
				cur_write_data <= 32'h0;
				
				pass <= 1;
				j <= 0;
				
				state <= READ;
					
			end
		end

		READ: begin

			if (offset < 20) begin
		
				message[offset-1] <= mem_read_data;

				offset <= offset + 1;

				cur_we <= 1'b0;

				state <= READ;

			end

			else begin
				
				n <= 0;
				i <= 0;
				offset <= 0;
				state <= BLOCK1;
				
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
			
			fh0 <= 32'h6a09e667;
			fh1 <= 32'hbb67ae85;
			fh2 <= 32'h3c6ef372;
			fh3 <= 32'ha54ff53a;
			fh4 <= 32'h510e527f;
			fh5 <= 32'h9b05688c;
			fh6 <= 32'h1f83d9ab;
			fh7 <= 32'h5be0cd19;
			
			a <= 32'h6a09e667;
			b <= 32'hbb67ae85;
			c <= 32'h3c6ef372;
			d <= 32'ha54ff53a;
			e <= 32'h510e527f;
			f <= 32'h9b05688c;
			g <= 32'h1f83d9ab;
			h <= 32'h5be0cd19;
			
			n <= 0;
			i <= 0;
			state <= COMPUTE1;
			
		end


    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
		COMPUTE1: begin
	// 64 processing rounds steps for 512-bit block 

			if(i<64) begin
							
				w[0]<=w[1];
				w[1]<=w[2];
				w[2]<=w[3];
				w[3]<=w[4];
				w[4]<=w[5];
				w[5]<=w[6];
				w[6]<=w[7];
				w[7]<=w[8];
				w[8]<=w[9];
				w[9]<=w[10];
				w[10]<=w[11];
				w[11]<=w[12];
				w[12]<=w[13];
				w[13]<=w[14];
				w[14]<=w[15];
				w[15]<=wtnew(w);
				
				{a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[0], i);
				
				i <= i+1;
				state <= COMPUTE1;
				
			end
		
			else begin 
			
				fh0 <= fh0 + a;
				fh1 <= fh1 + b;	
				fh2 <= fh2 + c;	
				fh3 <= fh3 + d;	
				fh4 <= fh4 + e;	
				fh5 <= fh5 + f;	
				fh6 <= fh6 + g;
				fh7 <= fh7 + h;			

				i<=0;
				n<=0;
				state <= BLOCK2;	
				
			end
			
		end
		
	 
		BLOCK2: begin
			
			if(n<NUM_NONCES) begin
				
				wn[n][0] <= message[16];
				wn[n][1] <= message[17];
				wn[n][2] <= message[18];
				wn[n][3] <= n+j;	
				wn[n][4] <= 32'h80000000;
				wn[n][5] <= 32'h00000000;
				wn[n][6] <= 32'h00000000;
				wn[n][7] <= 32'h00000000;
				wn[n][8] <= 32'h00000000;
				wn[n][9] <= 32'h00000000;
				wn[n][10] <= 32'h00000000;
				wn[n][11] <= 32'h00000000;
				wn[n][12] <= 32'h00000000;
				wn[n][13] <= 32'h00000000;
				wn[n][14] <= 32'h00000000;
				wn[n][15] <= 32'd640;
				
				ha[n][0] <= fh0;
				ha[n][1] <= fh1;
				ha[n][2] <= fh2;
				ha[n][3] <= fh3;
				ha[n][4] <= fh4;
				ha[n][5] <= fh5;
				ha[n][6] <= fh6;
				ha[n][7] <= fh7;
				
				an[n] <= fh0;
				bn[n] <= fh1;
				cn[n] <= fh2;
				dn[n] <= fh3;
				en[n] <= fh4;
				fn[n] <= fh5;
				gn[n] <= fh6;
				hn[n] <= fh7;
				
				n <= n+1;
				state <= BLOCK2;
				
			end
			
			else begin
				
				n<=0;
				i<=0;
				state <= COMPUTE2;
				
			end
		
		end	
		
		COMPUTE2: begin
	// 64 processing rounds steps for 512-bit block 
			if(n<NUM_NONCES) begin
	
				if(i<64) begin			
					
					wn[n][0]<=wn[n][1];
					wn[n][1]<=wn[n][2];
					wn[n][2]<=wn[n][3];
					wn[n][3]<=wn[n][4];
					wn[n][4]<=wn[n][5];
					wn[n][5]<=wn[n][6];
					wn[n][6]<=wn[n][7];
					wn[n][7]<=wn[n][8];
					wn[n][8]<=wn[n][9];
					wn[n][9]<=wn[n][10];
					wn[n][10]<=wn[n][11];
					wn[n][11]<=wn[n][12];
					wn[n][12]<=wn[n][13];
					wn[n][13]<=wn[n][14];
					wn[n][14]<=wn[n][15];
					wn[n][15]<=wtnew(wn[n]);
					
					{an[n],bn[n],cn[n],dn[n],en[n],fn[n],gn[n],hn[n]} <= sha256_op(an[n], bn[n], cn[n], dn[n], en[n], fn[n], gn[n], hn[n], wn[n][0], i);
						
					i <= i+1;
					state <= COMPUTE2;
					
				end	
					
				else begin			
			
					ha[n][0] <= ha[n][0] + an[n];
					ha[n][1] <= ha[n][1] + bn[n];	
					ha[n][2] <= ha[n][2] + cn[n];	
					ha[n][3] <= ha[n][3] + dn[n];	
					ha[n][4] <= ha[n][4] + en[n];	
					ha[n][5] <= ha[n][5] + fn[n];	
					ha[n][6] <= ha[n][6] + gn[n];
					ha[n][7] <= ha[n][7] + hn[n];
					
					n <= n+1;
					i <= 0;
					state <= COMPUTE2;	
									
				end
						
			end
			
			else begin
			
				n<=0;
				i<=0;
				state <= BLOCK3;
			
			end

		end
	 
		BLOCK3: begin
		
			if(n<NUM_NONCES) begin
				
				wn[n][0] <= ha[n][0];
				wn[n][1] <= ha[n][1];
				wn[n][2] <= ha[n][2];
				wn[n][3] <= ha[n][3];
				wn[n][4] <= ha[n][4];
				wn[n][5] <= ha[n][5];
				wn[n][6] <= ha[n][6];
				wn[n][7] <= ha[n][7];
				wn[n][8] <= 32'h80000000;
				wn[n][9] <= 32'h00000000;
				wn[n][10] <= 32'h00000000;
				wn[n][11] <= 32'h00000000;
				wn[n][12] <= 32'h00000000;
				wn[n][13] <= 32'h00000000;
				wn[n][14] <= 32'h00000000;
				wn[n][15] <= 32'd256;
				
				ha[n][0] <= 32'h6a09e667;
				ha[n][1] <= 32'hbb67ae85;
				ha[n][2] <= 32'h3c6ef372;
				ha[n][3] <= 32'ha54ff53a;
				ha[n][4] <= 32'h510e527f;
				ha[n][5] <= 32'h9b05688c;
				ha[n][6] <= 32'h1f83d9ab;
				ha[n][7] <= 32'h5be0cd19;
				
				an[n] <= 32'h6a09e667;
				bn[n] <= 32'hbb67ae85;
				cn[n] <= 32'h3c6ef372;
				dn[n] <= 32'ha54ff53a;
				en[n] <= 32'h510e527f;
				fn[n] <= 32'h9b05688c;
				gn[n] <= 32'h1f83d9ab;
				hn[n] <= 32'h5be0cd19;
				
				n <= n+1;
				state <= BLOCK3;
				
			end
			
			else begin		
		
				n<=0;
				i<=0;
				state <= COMPUTE3;
			
			end
			
		end
		
		
		COMPUTE3: begin
		
			if(n<NUM_NONCES) begin
	
				if(i<64) begin			
				
					wn[n][0]<=wn[n][1];
					wn[n][1]<=wn[n][2];
					wn[n][2]<=wn[n][3];
					wn[n][3]<=wn[n][4];
					wn[n][4]<=wn[n][5];
					wn[n][5]<=wn[n][6];
					wn[n][6]<=wn[n][7];
					wn[n][7]<=wn[n][8];
					wn[n][8]<=wn[n][9];
					wn[n][9]<=wn[n][10];
					wn[n][10]<=wn[n][11];
					wn[n][11]<=wn[n][12];
					wn[n][12]<=wn[n][13];
					wn[n][13]<=wn[n][14];
					wn[n][14]<=wn[n][15];
					wn[n][15]<=wtnew(wn[n]);
					
					{an[n],bn[n],cn[n],dn[n],en[n],fn[n],gn[n],hn[n]} <= sha256_op(an[n], bn[n], cn[n], dn[n], en[n], fn[n], gn[n], hn[n], wn[n][0], i);
						
					i <= i+1;
					state <= COMPUTE3;
					
				end	
					
				else begin			
			
					ha[n][0] <= ha[n][0] + an[n];
					ha[n][1] <= ha[n][1] + bn[n];	
					ha[n][2] <= ha[n][2] + cn[n];	
					ha[n][3] <= ha[n][3] + dn[n];	
					ha[n][4] <= ha[n][4] + en[n];	
					ha[n][5] <= ha[n][5] + fn[n];	
					ha[n][6] <= ha[n][6] + gn[n];
					ha[n][7] <= ha[n][7] + hn[n];
					
					n <=n+1;
					i<=0;
					state <= COMPUTE3;	
			
				end
						
			end
			
			else begin
			
				offset <= 0;
				
				n<=0;
				i<=0;
				state <= WRITE;
			
			end  				
	
		end
	 
		WRITE: begin
	
			if(i<NUM_NONCES) begin
			
				cur_addr <= output_addr + i + j;
				cur_write_data <= ha[i][0];
				cur_we <= 1'b1;
				
				state <= WRITE;
				i <= i+1;
				
			end
			
			else begin
				
				if(pass==1)begin
					
					pass<=pass-1;
					state <= BLOCK2;
					i<=0;
					n<=0;
					j<=8;
					
				end
				
				else begin
				
					state <= IDLE;
					i<=0;
					j<=0;
				
				end
				
			end
			
		end
		
		
	endcase
end

assign done = (state == IDLE);
	
endmodule
