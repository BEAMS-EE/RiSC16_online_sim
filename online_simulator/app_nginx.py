#!/usr/bin/python
# -*- coding: utf8 -*-

import os, cgi, sys
from flask import abort, Flask, request, redirect, url_for, send_from_directory, request, Response, flash, render_template, g, send_file
from werkzeug.utils import secure_filename
import time, datetime
from multiprocessing import Pool
import traceback
import re
from risc16 import risc16


LOG_FOLDER="log/"
UPLOAD_FOLDER="upload/"
MODULE_FOLDER="modules/"

from modules import exercise

global jobs_pending
jobs_pending=0
jobs_count=0
#jobs_pending_mutex=mutex.mutex()
start_time=time.time()
def get_date_fmt_file(date):
    str=date.strftime("%Y-%m-%d_%H-%M")
    return str

def process_file_to_log(call_param):
    global jobs_pending
    print call_param
    filename=call_param['filename']
    trace=call_param['trace']
    digest=call_param['digest']
    exec_time=call_param['exec']
    test_file = call_param['test_file']
    archi = call_param['archi']
    unsigned = call_param['unsigned']

    name,ext=filename.rsplit('.', 1)
    outf_c=os.path.join(LOG_FOLDER,name+".log_tmp")
    outf=os.path.join(LOG_FOLDER,name+".log")
    fo=open(outf_c,"w+",1)

    print "add job {0}, trace:{1}, digest:{2}, exec time:{3}, unsigned:{4}:".format(filename,trace,digest,exec_time,unsigned)
    print "init risc 16"
    try:
        risc=risc16.RISC16(trace=trace, digest=digest, logfile=fo, IS=archi, unsigned=unsigned)

        exo = exercise(fo)
        test_vectors = exo.get_inout(test_file)
        exo.launch_test(call_param, risc)

    except Exception, err:
        print >>fo,traceback.format_exc()
    fo.close()

    os.rename(outf_c,outf)
    return 0
    #for line in f:
        ##time.sleep(1)
        ##for i in x: s+=i#use CPU
        #fo.write(line)
        #fo.flush()
    #jobs_pending-=1
    #print jobs_pending


pool = Pool()
app = Flask(__name__)
app.secret_key = 'some_secret'
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024
app.config['UPLOAD_FOLDER']=UPLOAD_FOLDER
app.config['MAX_JOBS_WAITING']=1000


@app.route('/log/<filename>.html')
def serve_reports(filename):
    #print os.path.join(LOG_FOLDER,filename)
    filename+=".log"
    print filename
    #attachment_filename=filename.rsplit('.', 1)[0]+".html"
    outf=os.path.join(LOG_FOLDER,filename)
    if os.access(outf, os.R_OK):
    #out_html=os.path.join(LOG_FOLDER,attachment_filename)
        f=open(outf)
        log="\n"
        i=0
        for line in f:
            #line=cgi.escape(line, quote=True)
            #log+="{0:3}-  {1}".format(i,line)
            log+="{1}".format(i,line.decode('utf-8'))
            i+=1
        #print log
        return render_template('log_done.html', filename=filename, log_content=log, status="download")
    else:
        return abort(404)
    #return     send_from_directory(LOG_FOLDER,filename=filename,mimetype="text/html",  as_attachment=True,)


@app.route('/img/<filename>')
def get_image(filename):
    return send_file("log/"+filename+".png", mimetype="image/png")


@app.route('/log_txt/<filename>.log')
def serve_reports_txt(filename):
    #print os.path.join(LOG_FOLDER,filename)
    #attachment_filename=filename.rsplit('.', 1)[0]+".html"
    filename+=".log"
    outf=os.path.join(LOG_FOLDER,filename)
    if os.access(outf, os.R_OK):
        outf=os.path.join(LOG_FOLDER,filename)
        f=open(outf)
        log=filename+"\n"
        i=0
        for line in f:
            #line=cgi.escape(line, quote=True)
            #log+="{0:3}-  {1}".format(i,line)
            line=re.sub(r'<.+?>', '', line)
            line=re.sub(r'&nbsp;', '', line)
            log+="{1}".format(i,line.decode('utf-8'))
            i+=1
        #print log
        return log #render_template('log_download.html', filename=filename, log_content=log)
    else:
        return abort(404)

@app.route('/code/<filename>')
def serve_code(filename):
    #print os.path.join(LOG_FOLDER,filename)
    #attachment_filename=filename.rsplit('.', 1)[0]+".html"
    return     send_from_directory(UPLOAD_FOLDER,filename=filename,mimetype="text/plain", as_attachment=True)

@app.route('/code_html/<filename>')
def serve_code_html(filename):
    #print os.path.join(LOG_FOLDER,filename)
    #attachment_filename=filename.rsplit('.', 1)[0]+".html"
    outf=os.path.join(UPLOAD_FOLDER,filename)
    if os.access(outf, os.R_OK):
        f=open(outf)
        log=u"\n<pre>"
        i=0
        for line in f:
            #line=cgi.escape(line, quote=True)
            #log+="{0:3}-  {1}".format(i,line)
            log+=u"{1}".format(i,line.decode('utf-8'))
            i+=1
        #print log
        log+="</pre>"
        filename=filename.rsplit('.', 1)[0] #strip the extension
        return render_template('code_html.html', filename=filename, code_content=log)

    else:
        print "File does not exist, wait...",os.path.join(LOG_FOLDER,filename)
        #pending=pool._taskqueue.qsize()
        print "jobs pending : ",jobs_pending

        return render_template('log_done.html', pending=jobs_pending)


@app.route('/log_page/<filename>')
def log_page(filename):

    outf_tmp=os.path.join(LOG_FOLDER,filename+"_tmp")
    outf=os.path.join(LOG_FOLDER,filename)
    global jobs_pending
    if os.access(outf, os.R_OK):
        f=open(outf)
        log="\n"
        i=0
        for line in f:
            #line=cgi.escape(line, quote=True)
            #log+="{0:3}-  {1}".format(i,line)
            log+="{1}".format(i,line.decode('utf-8'))
            i+=1
        #print log
        filename=filename.rsplit('.', 1)[0] #strip the extension
        return render_template('log_done.html', filename=filename, log_content=log, status="done")

    elif os.access(outf_tmp, os.R_OK):
        f=open(outf_tmp)
        log=""
        i=0
        for line in f:
            #line=cgi.escape(line, quote=True)
            #log+="{0:3}-  {1}".format(i,line)
            log+="{1}".format(i,line.decode('utf-8'))
            i+=1
        #print log
        return render_template('log_done.html', filename=filename, log_content=log, status='pending')
    else:
        print "File does not exist, wait...",os.path.join(LOG_FOLDER,filename),
        #pending=pool._taskqueue.qsize()
        print "jobs pending : ",jobs_pending

        return render_template('log_done.html', pending=jobs_pending, status='wait')
    #just in case
    return redirect(url_for('upload'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ["txt",] #,"html"]

def update_jobs_pending(none):
    global jobs_pending, jobs_count
    jobs_pending-=1
    jobs_count+=1
    #print jobs_pending

@app.route('/', methods=['GET', 'POST'])
def upload():
    global jobs_pending
    g.list_exo = [exo for exo in os.listdir(MODULE_FOLDER)]

    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename) and file.content_length<app.config['MAX_CONTENT_LENGTH'] and jobs_pending<app.config['MAX_JOBS_WAITING']:
            print "loading..."
            filename = secure_filename(file.filename)
            name,ext=filename.rsplit('.', 1)
            filename=name+"-"+get_date_fmt_file(datetime.datetime.now())+"."+ext
            filename_log=name+"-"+get_date_fmt_file(datetime.datetime.now())+".log"
            print filename, filename_log
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            #get parameters
            #print request.form
            #if request.form.has_key("asm_digest"): print "asm digest asked"
            #if request.form.has_key("trace"): print "trace asked"
            if request.form.has_key("exec"):
                exec_instr = int(request.form["exec"])
            else:
                exec_instr = 100000
            if request.form.has_key("exo"):
                test_file = str(request.form["exo"])
            if request.form.has_key("archi"):
                archi = str(request.form["archi"])
            if request.form.has_key('logic'):
                unsigned = int(request.form["logic"])

            call_param={'filename':filename,'digest':request.form.has_key("asm_digest"),'trace':request.form.has_key("trace"), 'exec':exec_instr, 'test_file':test_file, 'archi':archi, 'unsigned':unsigned}

            print "adding job to the pool"
            pool.map_async(process_file_to_log, (call_param,),1, update_jobs_pending)
            #process_file_to_log(call_param, test_file)
            #update_jobs_pending(1)
            #jobs_pending=res._number_left

            jobs_pending+=1
            with app.test_request_context():
                log_page=url_for('log_page',filename=filename_log)
            #print jobs_pending
            return redirect(log_page)
        else:
            if jobs_pending>=app.config['MAX_JOBS_WAITING']:
                flash("Too much jobs for the moment: {0}.<br>\n".format(jobs_pending))
            if not file:
                flash("Empty filename.\n")
            if not allowed_file(file.filename):
                print "forbidden file", file.filename
                flash("Wrong file format.\n")
            if file.content_length>app.config['MAX_CONTENT_LENGTH']:
                print "File too big", file.filename
                flash("File too big.\n")
            return render_template('index_2.html')

    return render_template('index_2.html')


#@app.route('/', methods=['GET', 'POST'])
#def upload_file():
#    return render_template('index.html')

#@app.errorhandler(403)
#def app_forbidden(e):
    #return 'application itself says no', 403
@app.route('/admin')
def admin():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    if ip=="127.0.0.1":
        global jobs_count, jobs_pending, start_time
        up=time.time()-start_time
        list_jobs=""
        all_files= []
        for (dirpath, dirnames, filenames) in os.walk(UPLOAD_FOLDER):
            all_files.extend(filenames)

        def get_creation_time(filename):
            path=os.path.join(UPLOAD_FOLDER,filename)
            return os.path.getctime(path)

        all_files=sorted(all_files,None,get_creation_time)


        for f in all_files:
            #print f
            filename=f.rsplit('.', 1)[0]
            code_name=filename+".txt"
            code_name="""<a href="{1}" download title="Download code">{0}.txt</a> <a href="{1}"  title="See code">see</a>""".format(filename, url_for('serve_code_html',filename=filename+".txt"))
            log_name=os.path.join(LOG_FOLDER,filename+".log")
            log_name="""<a href="{0}" title="Report page">report</a>""".format(url_for('log_page',filename=filename+".log"))
            #report_txt="""<a href="{0}" title="Download code">Download code.</a>""".format(url_for('serve_reports_txt',filename=filename+".log"))
            #report_html=url_for('serve_reports',filename=filename+".html")
            outf_tmp=os.path.join(LOG_FOLDER,filename+".log_tmp")
            outf=os.path.join(LOG_FOLDER,filename+".log")
            if os.access(outf, os.R_OK):
                status="""<span style="color:green">Done</span>"""
            elif os.access(outf_tmp, os.R_OK):
                status="""<span style="color:blue">Pending</span>"""
            else:
                status="""<b><span style="color:red">Waiting</span></b>"""
            list_jobs+="<tr><td>{2}</td> <td>{0}</td><td>{1}</td></tr>\n".format(code_name,log_name, status)
        try:
            treq=(time.time()-start_time)/jobs_count
        except ZeroDivisionError:
            treq=0
        return render_template('admin.html', pending=jobs_pending, count=jobs_count, treq=treq, lines=list_jobs )
    return abort(403) #redirect(403)


if __name__ == '__main__':
#	app.debug=True
    app.run(host='0.0.0.0',port=8080)
#	while(1):
#		try:
#			app.run(host='0.0.0.0',port=8080)
#			print "Server fail, restart..."
#			sleep(1)
#		except OSError:
#			pass
