#!/usr/bin/python

import sys
import string
import os

def str_to_int(str): #could be replaced by int(x,0) ?
	if "0x" in str: num=int(str,16)
	elif "0b" in str: num=int(str,2)
	else: num=int(str)
	#if str[0]=="0": return int(str,8)
	#if num>0x7fff:num-=0x10000 #ensure all registers are signed
	return num

def imm_to_sig(i,size):
	if i&2**(size-1) and i>=0:
		return i-2**size
	return i
	
def sig_ext(i,size_in, size_out):
	if i&2**(size_in-1):#if <0
		return i|(2**(size_out-size_in)-1)<<size_in
	return i
	
quiet=1 
trace=len(sys.argv)>1 and sys.argv[1]=="trace"
if "noquiet" in sys.argv: quiet=0

class RISC16:
	def __init__(self,trace=False, digest=True, logfile=None, IS="IS0", unsigned=0):
		self.unsigned=unsigned
		if "unsigned" in sys.argv:
			self.unsigned=1
		self.registers=[0]*8
		self.pc=0
		self.ram=[0]*256
		self.rom=["nop"]*2048
		self.rom[-2]="halt"
		self.instruction_count=0
		self.link={}
		self.IS=IS
		self.maxint=2**16-1
		self.minint=0 #-2**15
		self.error_message=""
		self.movi_extra_param=0
		
		if IS=="IS2":# immed values are 12 bits wide in IS2
			self.immed_min=-2048*(1-self.unsigned)
			self.immed_max= 2047*(1+2*self.unsigned)
			self.immed_jump_min=-2048
			self.immed_jump_max= 2047
			self.immed_overflow_min=-128*(1-self.unsigned)
			self.immed_overflow_max=127*(1+2*self.unsigned)
			self.registers=[0]*64
		else:#in IS0/1 immed are 7 bits wide
			self.immed_min=-64*(1-self.unsigned)
			self.immed_max= 63*(1+2*self.unsigned)
			self.immed_jump_min=-64
			self.immed_jump_max= 63
			self.immed_overflow_min=-8
			self.immed_overflow_max=7
		if IS=="IS1":
			self.registers=[0]*64
		self.nullfile=open(os.devnull,"w")
		if logfile:
			self.logfile=logfile #open("logfile","w+")
			#self.logfile.write("\n\n\n")
		else:
			self.logfile=sys.stdout
		if trace:
			self.tracefile=self.logfile
		else:
			self.tracefile=self.nullfile
		
		if digest:
			self.digestfile=self.logfile
		else:
			self.digestfile=self.nullfile
		#print "init done"
		#self.exec_time=exec_time
		
	def reset(self):
		if self.IS in ("IS1", "IS2"):
			self.registers=[0]*64
		else:
			self.registers=[0]*8
		self.pc=0
		#self.ram=[0]*256
#		self.rom=["nop"]*256
		self.instruction_count=0
		#self.link={}
	def print_reg(self,num, filelog=None):
		if not quiet: print >>filelog,"reg{0} : {1}".format(num,hex(self.registers[num]))
	def print_mem(self,num, filelog=None):
		if not quiet : print >>filelog,"mem[{0}] : {1}".format(num,hex(self.ram[num]))
	def out_reg(self,num):
		return " reg{0}   : {1:0=#06x}".format(num,self.registers[num])
	def out_mem(self,num):
		return "mem[{0:0=#04x}]: {1:0=#06x}".format(num,self.ram[num])
	def get_register(self, num):
		return self.registers[num]
	def set_register(self, num, value):
		self.registers[num]=value
	def assert_reg(self, num, value):
		return self.registers[num]==value
	def set_error_message(self, message, PC=0):
		self.error_message+="ERROR @{0:0=#06x}: {1}\n".format((PC)*(PC>0), message)
	def get_error_message(self):
		return self.error_message
	def clear_error_message(self):
		self.error_message=""
	def txt_to_instr(self, line):
		#convert a line to std
		line=line.lower()
		line=line.strip()
		line=line.split("//",1)[0]
		if ":" in line:
			label,instr=line.split(":",1)
			instr=instr.strip()
		else:
			label=""
			instr=line
		instr=instr.strip()
		label=label.strip()
		return [label,instr]
		
	def instr_process(self, instr):
		instr=instr.lower()
		instr=instr.strip()
		#if not quiet: print "x",instr
		op=string.split(instr,None,1)[0]
		op=op.strip()
		#if not quiet: print "opp",op
		try:
			param=string.split(instr,None,1)[1].split(",")
			param=map(str.strip,param)
			#print "p:",param
			try:
				param=map(str_to_int,param)
			except ValueError:
				#print "label found"
				param=string.split(instr,None,1)[1].split(",")
				#print param
				if "beq" in instr or instr[:2] in ("bl", "bg") : 
					try:
						param=[int(param[0]),int(param[1]),param[2].strip()]
					except ValueError:
						print >>self.digestfile,"Undefined registers in BEQ"
						param=[]
				#print 
				#if instr == "addi":
					#print "addi"
					#try:
						#param=[int(param[0]),int(param[1]),int(param[2]),param[3].strip()] #label in overflow management
					#except ValueError:
						
						#print "x",param
				try:
					if instr[:3] in ("add", "sub", "shl", "sha"):  
						#print "found overflow label"
						param=[int(param[0]),int(param[1]),int(param[2]),param[3].strip()] #label in overflow management
				except ValueError: #if exception in add(i)
					param=[int(param[0]),int(param[1]),param[2].strip()] #label in addi instr.
					#print "addiu", param
		except IndexError:
			param=[]
		#print op,param
		return [op,param]
		
	def movi_split(self, instr):
		op, param=self.instr_process(instr)
		#print param
		try:
			param=map(str_to_int,param)
		except:pass
		try:
			instr1="lui  {0},{1}".format(param[0],param[1]>>6)
			instr2="addi {0},{0},{1}".format(param[0], param[1]&63)
			if len(param)>2: self.movi_extra_param=1
		except TypeError:
			print >>self.digestfile, "ERROR: cannot parse:",instr
			#self.set_error_message( "ERROR: cannot parse:: "+instr, line)
			return ["halt", "halt"]
		return [instr1, instr2]
		
	def load_rom(self, filename):
		f=open(filename, "r")
		i=0
		line=0
		if self.unsigned:
			print >>self.digestfile,"/!\\ Assuming unsigned arithmetics /!\\"
		for l in f:
			l=l.split("//",1)[0]
			l=l.strip()
			line+=1
			if not l : continue
			#if not quiet: print l
			if l[0]=="@":
				i=str_to_int(l[1:])
				print >>self.digestfile,"absolute address, continuing at @{0:0=#06x}".format(i)
				continue
				
			label,instr=self.txt_to_instr(l)
			#print "i:",instr
			if label:
				if ',' in label:
					print >>self.digestfile, "WARNING: label contains ',', maybe unexpected ':'",label
					self.set_error_message( "label contains ',', maybe unexpected ':': "+label, line)
				if not self.link.has_key(label):
					self.link[label]=i
					print >>self.digestfile, "label : {0} @{1:0=#06x}".format(label,i)
				else:
					print >>self.digestfile, "WARNING: redefined label",label
					self.set_error_message( "redefined label: "+label, line)
				
			if instr:
				self.rom[i]=instr
				#print instr
				op, param=self.instr_process(instr)
				#check if instruction exists
				if op not in ("movi", "halt", "add", "addi", "nand", "lui", "lw", "sw", "beq", "jalr", "reset", "nop", "sub", "nor", "xor", "or", "and", "xnor", "bl", "shl", "sha", "shifti", "mul", "bg", "trap"):
					self.set_error_message("Undefined instruction '{0}'".format(instr),self.pc)
					print >>self.digestfile,"Undefined instruction: '{0}'".format(instr,self.pc)
				
				#verify if valid in IS0
				if self.IS=="IS0" and op in ("sub", "nor", "xor", "or", "and", "xnor", "bl", "shl", "sha", "shifti", "mul", "bg"):
					self.set_error_message( "Undefined instruction in IS0 '{0}'".format(instr),self.pc)
					print >>self.digestfile,"Undefined instruction in IS0 : '{0}'".format(instr,self.pc)
				#... in IS1
				if self.IS=="IS1" and op in ("mul", "bg"):
					self.set_error_message( "Undefined instruction in IS1 '{0}'".format(instr),self.pc)
					print >>self.digestfile,"Undefined instruction in IS1 : '{0}'".format(instr,self.pc)
					
				#if op in ("movi", "halt", "add", "addi", "nand", "lui", "lw", "sw", "beq", "jalr", "reset", "nop", "sub", "nor", "xor", "or", "and", "xnor", "bl", "shl", "sha", "shifti", "mul", "bg"):
				
				#0 params
				if op in ("halt", "reset", "nop") and len(param)>0 :
					self.set_error_message( "Too many parameters for instruction '{0}'".format(instr),self.pc)
					print >>self.digestfile,"Too many parameters for instruction '{0}'".format(instr,self.pc)
				#1 param
				if len(param)==1 and op in ("movi", "lui","addi", "nand", "lw", "sw", "beq", "jalr", "nor", "xor", "or", "and", "xnor", "bl", "shifti", "mul", "bg","add", "sub", "sha", "shl"):
					self.set_error_message( "Missing parameter(s) for instruction '{0}'".format(instr),self.pc)
					print >>self.digestfile,"Missing parameter(s) for instruction '{0}'".format(instr,self.pc)
				#2 params
				if op in ("movi", "lui", "jalr") and len(param)!=2:
					self.set_error_message( "Instruction '{0}' takes exactly 2 parameters".format(instr),self.pc)
					print >>self.digestfile,"Instruction '{0}' takes exactly 2 parameters".format(instr,self.pc)
					
				#3 params
				if op in ("addi", "nand", "lw", "sw", "beq", "nor", "xor", "or", "and", "xnor", "bl", "shifti", "mul", "bg") and len(param)!=3:
					self.set_error_message( "Instruction '{0}' takes exactly 3 parameters".format(instr),self.pc)
					print >>self.digestfile,"Instruction '{0}' takes exactly 3 parameters".format(instr,self.pc)
				#3-4 params
				if op in ("add", "sub", "sha", "shl"):
					if self.IS=="ISO" and len(param)!=3 and op not in ("sub", "sha", "shl"):
						self.set_error_message( "Instruction '{0}' takes exactly 3 parameters".format(instr),self.pc)
						print >>self.digestfile,"Instruction '{0}' takes exactly 3 parameters".format(instr,self.pc)
					if self.IS in ("IS1," "IS2") and not (3<=len(param)<=4):
						self.set_error_message( "Instruction '{0}' takes 3 or 4 parameters in {1}".format(instr,self.IS),self.pc)
						print >>self.digestfile,"Instruction '{0}' takes 3 or 4 parameters in {1}".format(instr,self.IS,self.pc)
				
				if "movi" in instr.lower():
					instr1,instr2=self.movi_split(instr)
					if self.movi_extra_param:
						self.set_error_message("Extra parameter for MOVI instruction : "+instr, line)
						print >>self.digestfile, "Extra parameter for MOVI instruction: {0}".format(instr)
						self.movi_extra_param=0
					print >>self.digestfile,"@{0:0=#06x} : {1:10}: {2}".format(i,label,instr1)
					self.rom[i]=instr1
					i+=1
					print >>self.digestfile,"@{0:0=#06x} : {1:10}: {2}".format(i,"",instr2)
					self.rom[i]=instr2
				else:
					print >>self.digestfile,"@{0:0=#06x} : {1:10}: {2}".format(i,label,instr)
				
				i+=1
			
		print >>self.digestfile, self.error_message
		self.clear_error_message()
		print >>self.digestfile, "Instructions : ",i-1
	def link_list(self):
		print >>self.logfile,self.link
	
	def execute_instr(self, instr):
		op, param=self.instr_process(instr)
		overflow=0
		#undefined_instruction=1
		oldpc=self.pc
		if not quiet: print "op : {} , {}".format(op,param)
		pc_curr=self.pc
		ort=""
		mt=""
		pc=""
		
		
		#if op not in ("halt", "add", "addi", "nand", "lui", "lw", "sw", "beq", "jalr", "reset", "nop", "sub", "nor", "xor", "or", "and", "xnor", "bl", "shl", "sha", "shifti", "mul", "bg"):
			#self.set_error_message("Undefined instruction '{0}'@".format(op),self.pc)
			#print >>self.tracefile,"Undefined instruction '{0}'@{1}".format(op,self.pc)
			#return 1
		if "halt" == op: 
			return 1
		elif "add" == op:
			internal_result=self.registers[param[1]]+self.registers[param[2]]
			#check overflow
			#if not self.minint<=internal_result<=self.maxint:overflow=1	#overflow management
			#overflow computation from java simulator :
			if self.unsigned:
				overflow= not not (internal_result&0x10000)
			else:
				overflow= not not ((~(self.registers[param[1]]& 0x8000 ^ self.registers[param[2]]& 0x8000)) & (internal_result & 0x8000 ^  self.registers[param[1]]&  0x8000) )
			#print hex(overflow)
			#print hex(internal_result&0x18000)
			#if (internal_result&0x18000)==0x10000 or (internal_result&0x18000)==0x8000 :overflow=1
			#print "overflow in add", self.registers[param[1]],self.registers[param[2]]
			self.registers[param[0]]=(internal_result)&0xffff #still, we have to compute the result
			self.print_reg(param[0])
			ort=self.out_reg(param[0])
			self.pc+=1
		elif "addi" == op:
			#print param
			try:
				imm=imm_to_sig(param[2],7+self.unsigned)
				if not self.immed_min<=imm<=self.immed_max: 
					print >>self.tracefile,"error, immediate too big @", hex(self.pc), imm
					self.set_error_message("immediate too big: "+`param[2]`,self.pc)
				self.registers[param[0]]=(self.registers[param[1]]+imm)&0xffff
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
				
			except TypeError: #if label not defined, maybe constant is there
				#print "error"
				### FIXME TODO : the java simulator is bugged for labels in addi, they are interpreted as in beq, which is not correct.
				### I implemented it this way anyway to be consistent but once the java simulator is no longer used, remove the relative jump implementation
				try:
					imm= -self.pc+self.link[param[2]]-1
					#self.registers[param[0]]=(self.registers[param[1]]+self.link[param[2]])&0xffff #correct implementation
					
					self.registers[param[0]]=(self.registers[param[1]]+imm)&0xffff #java simulator implementation
					self.print_reg(param[0])
					ort=self.out_reg(param[0])
					self.pc+=1
				except KeyError: #if label not defined, maybe constant is there
					print >>self.logfile,"ERROR: undefined label, tried constant, failed"
					print >>self.tracefile,"ERROR : undefined label, tried constant, failed"
					self.set_error_message("Undefined label: "+`param[2]`,self.pc)
					return 1
			
		elif "nand" == op:
			self.registers[param[0]]=~(self.registers[param[1]]&self.registers[param[2]])&0xffff
			self.print_reg(param[0])
			ort=self.out_reg(param[0])
			self.pc+=1
		elif "lui" == op: # !!! lui different in IS2 !!! TODO
			imm= param[1] #sig_ext(param[1],10,16)
			if imm>2**10: 
				print >>self.tracefile,"lui, error, immediate too big @", self.pc, hex(param[1]),
				imm=imm>>6
				print >>self.tracefile,hex(imm)
			self.registers[param[0]]=(imm<<6)&0xffc0
			self.print_reg(param[0])
			ort=self.out_reg(param[0])
			self.pc+=1
		elif "lw" == op:
			imm=imm_to_sig(param[2],7+self.unsigned)
			try:
				addr=(self.registers[param[1]]+imm)&0xffff
				self.registers[param[0]]=self.ram[addr] #might check positivity here
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
			except IndexError:
				print >>self.logfile,"ERROR : RAM pointer (={0}) is out of range".format(addr)
				print >>self.tracefile,"ERROR : RAM pointer (={0}) is out of range".format(addr)
				self.set_error_message("ERROR : RAM pointer (={0}) is out of range".format(addr),self.pc)
				return 1
		elif "sw" == op:
			imm=imm_to_sig(param[2],7+self.unsigned)
			try:
				addr=(self.registers[param[1]]+imm)&0xffff
				self.ram[addr]=self.registers[param[0]]&0xffff #might check positivity here
				self.print_mem(addr)
				mt=self.out_mem(addr)
				self.pc+=1
			except IndexError:
				print >>self.logfile,"ERROR : RAM pointer (={0}) is out of range".format(addr)
				print >>self.tracefile,"ERROR : RAM pointer (={0}) is out of range".format(addr)
				self.set_error_message("ERROR : RAM pointer (={0}) is out of range".format(addr),self.pc)
				return 1
		elif "beq" == op:
			#if param[0]!= or not param[1]:
				#print >>self.logfile,"ERROR : undefined register"
				#print >>self.tracefile,"ERROR : undefined register"
				#self.set_error_message("ERROR : undefined register",self.pc)
				#return 1
			try:
				imm= -self.pc+self.link[param[2]]
			except KeyError: #if label not defined, maybe constant is there
				try:
					imm= int(param[2])+1
					#print >>self.logfile,"ERROR :undefined label, trying constant"
					#print >>self.tracefile,"ERROR : undefined label, trying constant"
				except ValueError:
					print >>self.logfile,"ERROR: undefined label, tried constant, failed"
					print >>self.tracefile,"ERROR : undefined label, tried constant, failed"
					self.set_error_message("Undefined label: "+`param[2]`,self.pc)
					return 1
				#print imm
			if not self.immed_jump_min<=imm<=self.immed_jump_max: 
				print >>self.logfile,"ERROR : jump too long"
				print >>self.tracefile,"ERROR : jump too long"
				self.set_error_message("jump too long",self.pc)
				return 1
			if self.registers[param[0]]==self.registers[param[1]]:
				self.pc=self.pc+imm
				
				#print "jump to :",self.pc
			else:
				self.pc+=1
			pc="pc: {0:0=#02x}".format(self.pc)
		elif "jalr" == op:
			oldpc=self.pc
			self.pc=self.registers[param[1]]
			self.registers[param[0]]=oldpc+1
			pc="pc: {0:0=#02x}".format(self.pc)
			ort=self.out_reg(param[0])+", "
		elif "reset" == op:
			self.pc=0
			print "reset"
		elif "nop" == op:
			#pass #nop
			self.pc+=1
		elif "trap"==op:
			print >>self.logfile,"TRAP triggered, you go to jail with message "+param[0]
			print >>self.tracefile,"TRAP triggered, you go to jail with message "+param[0]
			self.set_error_message("TRAP triggered, you go to jail with message "+param[0],self.pc)
			exit(2) #raise an error in makefile
			return 1
		else:
			pass
		if self.IS in ("IS1", "IS2"):
			#print "instruction in IS1/IS2"
			if "sub" == op:
				internal_result=self.registers[param[1]]-self.registers[param[2]]
				#check overflow
				#if self.minint>internal_result>self.maxint:overflow=1	#overflow management
				#from java simulator
				if not self.unsigned:
					overflow=not not (((self.registers[param[1]] & 0x8000 ^ self.registers[param[2]] & 0x8000)) & ~(internal_result & 0x8000 ^ self.registers[param[2]] & 0x8000))
				else:
					overflow=not not (internal_result<0)
				self.registers[param[0]]=(internal_result)&0xffff
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
			elif "nor" == op:
				self.registers[param[0]]=~(self.registers[param[1]]|self.registers[param[2]])&0xffff
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
			elif "xor" == op:
				self.registers[param[0]]=(self.registers[param[1]]^self.registers[param[2]])&0xffff
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
			elif "or" == op: #should be orthogonal with another instruction, no detection yet
				self.registers[param[0]]=(self.registers[param[1]]|self.registers[param[2]])&0xffff
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
			elif "and" == op: #should be orthogonal with another instruction, no detection yet
				self.registers[param[0]]=(self.registers[param[1]]&self.registers[param[2]])&0xffff
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
			elif "xnor" == op:
				self.registers[param[0]]=~(self.registers[param[1]]^self.registers[param[2]])&0xffff
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
			elif "bl" == op:
				#print param[2],self.link[param[2]]
				try:
					imm= -self.pc+self.link[param[2]]
				except KeyError: #if label not defined, maybe constant is there
					try:
							imm=int(param[2])+1
					except ValueError:
							print >>self.logfile,"undefined overflow jump"
							print >>self.tracefile,"undefined overflow jump"
							self.set_error_message("Undefined label: "+`param[2]`,self.pc)
							return 1
	

				#	imm= int(param[2])+1
				#	print >>self.logfile,"undefined label"
				#	print >>self.tracefile,"undefined label"
				#	self.set_error_message("Undefined label: "+`param[2]`,self.pc)
				#	return 1
					#print imm
				if not self.immed_jump_min<=imm<=self.immed_jump_max: 
					print >>self.logfile,"ERROR : jump too long, ignoring"
					print >>self.tracefile,"ERROR : jump too long, ignoring"
					self.set_error_message("jump too long",self.pc)
					return 1
				if self.unsigned:
					op1=self.registers[param[0]]&0xffff
					op2=self.registers[param[1]]&0xffff
				else:
					op1=self.registers[param[0]]-0x10000*(self.registers[param[0]]>0x7fff)
					op2=self.registers[param[1]]-0x10000*(self.registers[param[1]]>0x7fff)
				if op1<op2:
					self.pc=self.pc+imm
					#print "jump to :",self.pc
				else:
					self.pc+=1
				pc="pc: {0:0=#02x}".format(self.pc)
					
			elif "shl" == op:#test for <0 values
				#FIXME shl overflow implementation is not correct in the java simulator for this instruction
				if self.unsigned:
					sigval=self.registers[param[2]]&0xffff
					if sigval&0x8000:
						print >>self.logfile,"ERROR : negative shift on unsigned architecture"
						print >>self.tracefile,"ERROR : negative shift on unsigned architecture"
						self.set_error_message("negative shift on unsigned architecture",self.pc)
				else:
					sigval=self.registers[param[2]]-0x10000*(self.registers[param[2]]>0x7fff)
				#print sigval
				if sigval>=0:
					internal_result=(self.registers[param[1]]<<sigval)
				if sigval<0:
					internal_result=(self.registers[param[1]]>>-sigval) #|2**(16+self.registers[param[2]])<<(16+self.registers[param[2]])
				#print hex(internal_result)
				#check overflow
				overflow= not not (internal_result&~0xffff)
				#if self.minint>internal_result>self.maxint:overflow=1	#overflow management
				self.registers[param[0]]=internal_result&0xFFFF
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
				
			elif "sha" == op:
				if not self.unsigned:
					sigval=self.registers[param[2]]-0x10000*(self.registers[param[2]]>0x7fff)
				else:
					sigval=self.registers[param[2]]&0xFFFF
					if sigval&0x8000:
						print >>self.logfile,"ERROR : negative shift on unsigned architecture"
						print >>self.tracefile,"ERROR : negative shift on unsigned architecture"
						self.set_error_message("negative shift on unsigned architecture",self.pc)
				print sigval, hex(self.registers[param[1]])
				if sigval>=0:
					internal_result=(self.registers[param[1]]<<sigval)
				if sigval<0:
					internal_result=(self.registers[param[1]]>>-sigval)| (self.registers[param[1]]&0x8000!=0)*2**(-sigval)-1<<(16+sigval)
					print hex(internal_result)
					#check overflow
					#overflow= not not (internal_result&~0xffff)
				#if self.registers[param[2]]>0:
					#internal_result=(self.registers[param[1]]<<self.registers[param[2]])
				#if self.registers[param[2]]<0:
					#internal_result=(self.registers[param[1]]>>-self.registers[param[2]])|0x8000*(self.registers[param[1]]<0) #duplicate the bit sign
				#check overflow
				if not self.unsigned:
					overflow= not not ((internal_result&0x8000)^(self.registers[param[1]]&0x8000))
				else:
					overflow= not not (self.registers[param[1]]&0x8000)
				#if self.minint>internal_result>self.maxint:overflow=1	#overflow management
				self.registers[param[0]]=internal_result&0xFFFF	
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
				
			elif "shifti" == op:#test for <0 values
			#	print type(param[2])
				imm=imm_to_sig(param[2]&0x3F,6)
				
				if -16<=imm<=15:
					arith=0
				if 16<=imm<=63:
					arith=1
					imm-=32
				if -32<=imm<=-17:
					arith=1
					imm+=32
				if imm<-32 or imm>63 :
					self.set_error_message("Immediate too long in shifti instruction.",self.pc)
					return 1
				#print (imm), (param[2])
				#log_arith= not( param[2]&(~0x1f)&(1<<5)) #1 = logique, 0 = arith
				#print arith
				if imm>0:
					internal_result=(self.registers[param[1]]<<imm)&0xffff
				else:
					internal_result=(self.registers[param[1]]>>-imm)&0xffff |(arith!=0)*(self.unsigned==0)*(self.registers[param[1]]&0x8000!=0)*int(2**(-imm)-1)<<(16+imm)
				#print hex(internal_result), hex((arith!=0)*(self.unsigned==0)*(self.registers[param[1]]&0x8000!=0)*int(2**(-imm)-1)<<int(16+imm)), hex(self.registers[param[1]])
				self.registers[param[0]]=internal_result&0xffff
				self.print_reg(param[0])
				ort=self.out_reg(param[0])
				self.pc+=1
			else: pass
				
		if self.IS=="IS2":
			#print "instruction in IS2 only"
			if "mul" == op:
				if self.unsigned:
					op1=self.registers[param[1]]&0xffff
					op2=self.registers[param[2]]&0xffff
				else:
					op1=self.registers[param[1]]-0x10000*(self.registers[param[1]]>0x7fff)
					op2=self.registers[param[2]]-0x10000*(self.registers[param[2]]>0x7fff)
				prod=(op1*op2)&0xFFFFFFFF
				self.registers[param[0]]=prod&0xffff
				self.print_reg(param[0])
				
				if param[0]>1:
					self.registers[param[0]-1]=(prod>>16)&0xffff
					self.print_reg(param[0]-1)
					ort=self.out_reg(param[0]-1)
				ort+=self.out_reg(param[0])
				self.pc+=1	
			elif "bg" == op:
				#print param[2],self.link[param[2]]
				try:
					imm= -self.pc+self.link[param[2]]
				except KeyError: #if label not defined, maybe constant is there
					imm= int(param[2])+1
					print >>self.logfile,"undefined label"
					print >>self.tracefile,"undefined label"
					self.set_error_message("Undefined label: "+`param[2]`,self.pc)
					#print imm
				if not self.immed_jump_min<=imm<=self.immed_jump_max: 
					print >>self.logfile,"ERROR : jump too long, ignoring"
					print >>self.tracefile,"ERROR : jump too long, ignoring"
					self.set_error_message("jump too long",self.pc)
					return 1
				if self.unsigned:
					op1=self.registers[param[0]]&0xffff
					op2=self.registers[param[1]]&0xffff
				else:
					op1=self.registers[param[0]]-0x10000*(self.registers[param[0]]>0x7fff)
					op2=self.registers[param[1]]-0x10000*(self.registers[param[1]]>0x7fff)
				if op1>op2:
					self.pc=self.pc+imm
					#print "jump to :",self.pc
				else:
					self.pc+=1
				pc="pc: {0:0=#02x}".format(self.pc)
			else: pass
		self.registers[0]=0
		#if pc:
			#try:
				#pc+=self.link[
		#print overflow
		if self.IS!="IS0" and overflow and len(param)>3 and param[3] : #if overflow AND overflow management
			#print "overflow..."
			try:
				imm= -self.pc+self.link[param[3]]
			except KeyError:
				try:
					imm=imm_to_sig(param[3],4)
				except ValueError:
					print >>self.logfile,"undefined overflow jump"
					print >>self.tracefile,"undefined overflow jump"
					self.set_error_message("Undefined overflow: "+`param[2]`,self.pc)
					return 1
			#make the jump
			if self.immed_overflow_min<=imm<=self.immed_overflow_max:
				self.pc=self.pc+imm #because +1 already in add/sub/sh*
				pc=" pc: {0:0=#02x} (overflow)".format(self.pc)
			else:
				print >>self.logfile,"jump too long"
				print >>self.tracefile,"jump too long"
				self.set_error_message("jump too long",self.pc)
				return 1
		print >>self.tracefile, "PC:{0:0=#05x} {1:5} {2:10}\t{3}".format(pc_curr,op,', '.join(str(e) for e in param),ort+mt+pc)
		if oldpc==self.pc:
			print >>self.logfile,"ERROR: Undefined instruction or infinite loop"
			print >>self.tracefile,"ERROR: Undefined instruction or infinite loop"
			self.set_error_message("Undefined instruction or infinite loop",self.pc)
			return 1
		return 0
	
	def execute(self, instr_count=10**7):
		#just one instr
		#fetch
		print >>self.tracefile, "\n\n\n"
		start=self.instruction_count
		while(self.instruction_count<start+instr_count):
			instr=self.rom[self.pc]
			#if not quiet : 
			#print " pc:{0:3} : {1}".format(self.pc, instr)
			
			#execute
			#if "halt" in instr: break
			#increment PC
			#self.pc+=1
			try:
				if self.execute_instr(instr): break
			except IndexError:
				print >>self.logfile,"ERROR: Out of range register number"
				print >>self.tracefile,"ERROR: Out of range register number"
				self.set_error_message("ERROR: Out of range register number",self.pc)
				break;
			
			self.instruction_count+=1
		#print "instr_count", self.instruction_count
		pass
if __name__=="__main__":
	
	if "-h" in sys.argv or "--help" in sys.argv:
		print """risc 16 simulator\n syntax : risc16.py [IS0] file\n IS0= basic 8 instr\n IS1, IS2 : enhanced instruction sets """
		exit(0)
	
	IS="IS0"
	if "IS0" in sys.argv:
		IS="IS0"
	if "IS1" in sys.argv:
		IS="IS1"
	if "IS2" in sys.argv:
		IS="IS2"
	print "assuming IS:", IS
	risc=RISC16(IS=IS, trace=True)
	#print str_to_int("0xff")
	#print str_to_int("077")
	#print str_to_int("0b1101001")
	#print imm_to_sig(0b1111111,7)
	#print imm_to_sig(0b1000000,7)
	#print sig_ext(0x1ff, 10, 16)
	#risc.movi_split("movi 0, 0xff")
	if len(sys.argv)>1:
		try:
			risc.load_rom(sys.argv[-1])
			#print risc.get_error_message()
			#risc.clear_error_message()
		except IOError:
			
	#else:
			print "test program"
			risc.load_rom("test.txt")
			risc.reset()
			risc.execute( )
			exit(0)
	else:
		print "test program"
		risc.load_rom("test.txt")
		
		risc.reset()
		risc.execute(100)
		exit(0)
	#print "programme", len(risc.rom), "instructions."
	risc.link_list()
	print sys.argv[-1]
	
	risc.reset()
	#risc.rom[0:4]=["nop"]*4
	
	#risc.set_register(1,check_a)
	#risc.set_register(2,check_b)
	#risc.ram[0]=check_a
	#risc.ram[1]=check_b
	#print risc.rom[:16]
	risc.execute(1000)
	print risc.get_error_message()
	risc.clear_error_message()
	exit(0)
	#a=op1, b=op2, c=resultat
	check_list=[(0,0xff),(0xff,0),(0x7fff,7),(0xffff,7), (0xa060,0x88dc)]
	start_size_test=len(check_list)
	for i in range(0,16):
		#print "({0},{0}),".format((2<<i)-1)
		check_list.append(((2<<i)-1,(2<<i)-1))
		
	passed=0
	arg_size=0
	arg_size_fail=0
	k=0
	print "Instructions 0 to 3 changed to 'nop', let's test..." #, reg(1) and reg(2) initialised"
	for check_a,check_b in check_list:#[:1]:
		#print "check for 0x{0:x}x0x{1:x}".format(check_a,check_b)
		
			
		risc.reset()
		risc.rom[0:4]=["nop"]*4
		
		risc.set_register(1,check_a)
		risc.set_register(2,check_b)
		#risc.ram[0]=check_a
		#risc.ram[1]=check_b
		#print risc.rom[:16]
		risc.execute()
		if risc.assert_reg(4,(check_a*check_b)>>16) and risc.assert_reg(3,(check_a*check_b)&0xffff):
			print "{0:0=#06x} x {1:0=#06x} ={2:0=#010x}, passed\t(instr={3:8})".format(check_a,check_b,check_a*check_b, risc.instruction_count)
			passed+=1
			if k>=start_size_test and not arg_size_fail:
				arg_size+=1
		else:
			risc.print_reg(3)
			risc.print_reg(4)
			if k>=start_size_test: arg_size_fail=1
			print "{0:0=#06x} x {1:0=#06x}!={2:0=#010x}(={3:0=#010x}), FAILED!!! \t(instr={4:8})".format(check_a,check_b,check_a*check_b, risc.get_register(3)+(risc.get_register(4)<<16), risc.instruction_count)
		#print
		k+=1
		
	print "Tests : {0}, {2:3} passed => {1:.1%} passed".format(len(check_list), 1.0*passed/len(check_list), passed)
	print "Argument size : {0} bits".format(arg_size)
