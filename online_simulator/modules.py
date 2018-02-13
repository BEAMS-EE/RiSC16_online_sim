#/usr/bin/python
import re

import matplotlib as plt

# Force matplotlib to not use any Xwindows backend.
plt.use('Agg')

from pylab import *
import logging
import os




LOG_FOLDER="log/"
UPLOAD_FOLDER="upload/"
MODULE_FOLDER="modules/"

class exercise:
	def __init__(self, fo):#, call_param, risc16, jobs):
		#self.filename=call_param['filename']
		#self.trace=call_param['trace']
		#self.digest=call_param['digest']
		#self.exec_time=call_param['exec']
		#self.risc16 = risc16
		#self.jobs = jobs
		self.fo = fo
		self.tests = []
		self.pattern = re.compile("r(?P<registerin>\d)=(?P<value>\w+);") 
		self.failpa = ""
		self.passpa = ""
		self.arg = "off"
		self.start_test = 0
		self.graphpoints = []


	def get_inout(self, mod_file):
		in_filename = os.path.join(MODULE_FOLDER, mod_file)
		in_file = open(in_filename, 'r')
		text_list = in_file.readlines()
		failpattern = re.compile("# fail:(?P<failpa>.+)")
		passpattern = re.compile("# pass:(?P<passpa>.+)")
		argpattern = re.compile("# arg:(?P<arg>.+)")
		for line in text_list:
			i = self.pattern.findall(line)
			if i != [] : self.tests.append(i)
			listpaf = failpattern.findall(line)
			if listpaf: self.failpa = listpaf[0]
			listpap = passpattern.findall(line)
			if listpap: self.passpa = listpap[0]
			listarg = argpattern.findall(line)
			if listarg: 
				self.arg = 'on'
				self.start_test = int(listarg[0],0)


		in_file.close()
		return self.tests

	def launch_test(self, call_param, risc):
		filename=call_param['filename']
		trace=call_param['trace']
		digest=call_param['digest']
		exec_time=call_param['exec']
		risc = risc
		in_filename=os.path.join(UPLOAD_FOLDER,filename) 

		risc.load_rom(in_filename)
		risc.reset()
		test_size = len(self.tests)/2
		passed = 0
		arg_size = 0
		arg_size_fail = 0
		k = 0
		failed = 0

		for v_in,v_out in zip(*[iter(self.tests)]*2): #iter items 2 at a time
			risc.reset()
			for j,reg in enumerate(v_in): #reg is a tuple (nb of reg, value)
				risc.set_register(int(reg[0],0),int(reg[1],0))
				risc.rom[2*j]="lui  {0},{1}".format(int(reg[0],0),int(reg[1],0)>>6)
				risc.rom[2*j+1]="addi {0},{0},{1}".format(int(reg[0],0),int(reg[1],0)&63)

			risc.execute(exec_time)
			print >>self.fo,risc.get_error_message()
			risc.clear_error_message()
			for i,reg in enumerate(v_out): #reg is a tuple of output (nb of reg, value)
				if not risc.assert_reg(int(reg[0],0),int(reg[1],0)) and not failed:
					print "fail",i,reg[0],reg[1]
					failed = 1
					self.forge_html("failed", v_out, v_in, risc)
					if k >= self.start_test:
						arg_size_fail = 1

				elif i == (len(v_out) - 1) and not failed:
					print "passlast",i,reg[0],reg[1]
					self.forge_html("passed", v_out, v_in, risc)
					passed+=1
					if k >= self.start_test and not arg_size_fail:
						arg_size += 1
						self.graphpoints.append((arg_size,risc.instruction_count))

				else:
					print "test ok, failed 1st time or passed"

			k+=1
			failed = 0
			self.fo.flush()

		print >>self.fo,"<br>Tests : {0} <br>".format(test_size)
		try:
			pcent_passed=1.0*passed/test_size
			if pcent_passed<1.0:
				print >>self.fo,"""Only {0:3} passed tests => <b><span style="color:red">{1:.1%} passed</span></b><br>""".format(passed ,pcent_passed)
			else:
				print >>self.fo,"""All {0:3} tests passed => <span style="color:green">{1:.1%} passed</span><br>""".format(passed ,pcent_passed)
			#arg_size=0
			if self.arg is 'on': 
				if arg_size==15:
					print >>self.fo, """Argument size: <b><span style="color:orange">only {0} bits</span></b><br>""".format(arg_size)
				elif arg_size<14:
					print >>self.fo, """Argument size: <b><span style="color:red">only {0} bits</span></b><br>""".format(arg_size)
				else:
					print >>self.fo, """Argument size: <span style="color:green">{0} bits</span><br>""".format(arg_size)

				imgfile = self.generate_graph(filename)
				print >>self.fo, """<img src="/img/{0}" alt="Performance graph" width=500px>""".format(imgfile)
		except:
			pass



	def generate_graph(self, filename):
		plot(zip(*self.graphpoints)[0],zip(*self.graphpoints)[1], marker='o')
		print zip(*self.graphpoints)[0],zip(*self.graphpoints)[1]
		xlabel('Argument size')
		ylabel('Nb of instructions')
		title('Performance')
		name,ext=filename.rsplit('.', 1)
		imgfile=os.path.join(LOG_FOLDER,name+".png")
		savefig(imgfile)
		close()
		return name

	def forge_html(self, status, vout, vin, risc):
		mergeddict = self.forge_dict(vin, vout, risc)
		if status == 'passed':
			print >>self.fo,"""<tt><b><span style="color:green">Passed</span></b></tt>""",
			t = self.passpa.format(**mergeddict)
			print >>self.fo,"""{0}""".format(t),
			print >>self.fo,""",\t<tt>(instr={0:8})</tt><br>""".format(risc.instruction_count),

		elif status == 'failed':
			print >>self.fo, """<tt><b><span style="color:red">/!\ FAILED /!\</span></b></tt>""",
			y = self.failpa.format(**mergeddict)
			print >>self.fo, """{0}""".format(y),
			print >>self.fo, """,\t<tt>(instr={0:8})</tt><br>""".format(risc.instruction_count),


	def forge_dict(self, vin, vout, risc):
		mergeddict = {}
		for reg in vout:
			mergeddict['ro%s' % reg[0]] = int(reg[1],0)
			mergeddict['risc%s' % reg[0]] = risc.get_register(int(reg[0],0))
		for reg in vin:
			mergeddict['ri%s' % reg[0]] = int(reg[1],0)

		return mergeddict

