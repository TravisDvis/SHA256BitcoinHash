transcript on
if {[file exists rtl_work]} {
	vdel -lib rtl_work -all
}
vlib rtl_work
vmap work rtl_work

vlog -sv -work work +incdir+C:/Users/t3davis/Downloads/Final_Project-20220529T202801Z-001/Final_Project/simplified_sha256 {C:/Users/t3davis/Downloads/Final_Project-20220529T202801Z-001/Final_Project/simplified_sha256/simplified_sha256.sv}

