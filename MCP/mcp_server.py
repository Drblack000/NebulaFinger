#!/usr/bin/env python3
"""
NebulaFinger MCP Server
基于 FastMCP 框架为 NebulaFinger 指纹识别工具提供 MCP 接口
"""

import asyncio
import subprocess
import json
import os
import tempfile
import time
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from fastmcp import FastMCP
except ImportError:
    logger.error("请安装 fastmcp: pip install fastmcp")
    sys.exit(1)

class NebulaFingerMCP:
    def __init__(self, base_path: str = None):
        """
        初始化 NebulaFinger MCP 服务
        
        Args:
            base_path: NebulaFinger 工具的基础路径，如果不指定则使用当前目录
        """
        self.base_path = Path(base_path) if base_path else Path.cwd()
        self.exe_path = self.base_path / "NebulaFinger.exe"
        self.configs_path = self.base_path / "configs"
        
        # 检查文件是否存在
        if not self.exe_path.exists():
            logger.error(f"NebulaFinger.exe 未找到: {self.exe_path}")
            # 尝试在当前目录查找
            current_exe = Path.cwd() / "NebulaFinger.exe"
            if current_exe.exists():
                self.exe_path = current_exe
                self.base_path = Path.cwd()
                self.configs_path = self.base_path / "configs"
                logger.info(f"在当前目录找到 NebulaFinger.exe: {self.exe_path}")
            else:
                raise FileNotFoundError(f"NebulaFinger.exe 未找到")
        
        if not self.configs_path.exists():
            logger.error(f"configs 目录未找到: {self.configs_path}")
            raise FileNotFoundError(f"configs 目录未找到: {self.configs_path}")
        
        # 指纹库文件路径
        self.web_fingerprint_path = self.configs_path / "web_fingerprint_v4.json"
        self.service_fingerprint_path = self.configs_path / "service_fingerprint_v4.json"
        
        logger.info(f"NebulaFinger 路径: {self.exe_path}")
        logger.info(f"配置文件路径: {self.configs_path}")

    async def run_nebula_finger(self, args: List[str]) -> Dict[str, Any]:
        """
        运行 NebulaFinger 命令
        
        Args:
            args: 命令行参数列表
            
        Returns:
            包含执行结果的字典
        """
        try:
            # 构建完整命令
            cmd = [str(self.exe_path)] + args
            
            # 添加指纹库路径参数
            if "-w" not in args:
                cmd.extend(["-w", str(self.web_fingerprint_path)])
            if "-s" not in args:
                cmd.extend(["-s", str(self.service_fingerprint_path)])
            
            logger.info(f"执行命令: {' '.join(cmd)}")
            
            # 执行命令
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.base_path)
            )
            
            stdout, stderr = await process.communicate()
            
            return {
                "success": process.returncode == 0,
                "returncode": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "command": ' '.join(cmd)
            }
            
        except Exception as e:
            logger.error(f"执行命令时出错: {e}")
            return {
                "success": False,
                "error": str(e),
                "command": ' '.join(cmd) if 'cmd' in locals() else "未知命令"
            }

# 创建 FastMCP 实例
mcp = FastMCP("NebulaFinger")

# 初始化 NebulaFinger MCP 实例
try:
    # 可以通过环境变量或命令行参数指定基础路径
    base_path = os.environ.get('NEBULAFINGER_PATH', None)
    if len(sys.argv) > 1:
        base_path = sys.argv[1]
    
    nebula = NebulaFingerMCP(base_path)
except Exception as e:
    logger.error(f"初始化失败: {e}")
    sys.exit(1)

@mcp.tool()
async def debug_file_path(file_path: str) -> str:
    """
    调试文件路径，检查文件是否存在以及可能的路径问题
    
    Args:
        file_path: 要检查的文件路径
        
    Returns:
        文件路径调试信息
    """
    debug_info = []
    debug_info.append("=== 文件路径调试信息 ===")
    debug_info.append(f"输入路径: {file_path}")
    debug_info.append(f"工作目录: {nebula.base_path}")
    debug_info.append("")
    
    # 尝试不同的路径解析方式
    paths_to_check = [
        ("原始路径", Path(file_path)),
        ("相对于工作目录", nebula.base_path / file_path),
        ("当前工作目录", Path.cwd() / file_path),
    ]
    
    for desc, path in paths_to_check:
        debug_info.append(f"{desc}: {path}")
        debug_info.append(f"  - 绝对路径: {path.resolve()}")
        debug_info.append(f"  - 存在: {'是' if path.exists() else '否'}")
        
        if path.exists():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                debug_info.append(f"  - 文件大小: {path.stat().st_size} 字节")
                debug_info.append(f"  - 行数: {len(lines)}")
                debug_info.append(f"  - 非空行数: {len([line for line in lines if line.strip()])}")
                
                # 显示前几行内容
                if lines:
                    debug_info.append("  - 前3行内容:")
                    for i, line in enumerate(lines[:3]):
                        debug_info.append(f"    {i+1}: {line.strip()}")
            except Exception as e:
                debug_info.append(f"  - 读取错误: {e}")
        debug_info.append("")
    
    return "\n".join(debug_info)

@mcp.tool()
async def debug_command(
    target: str = "example.com",
    mode: str = "web", 
    output_html: bool = True
) -> str:
    """
    调试命令执行，查看完整的命令行和输出
    
    Args:
        target: 测试目标
        mode: 扫描模式
        output_html: 是否生成HTML
        
    Returns:
        详细的调试信息
    """
    args = ["-u", target, "-m", mode]
    
    html_file_path = None
    if output_html:
        html_filename = f"debug_scan_{target.replace('://', '_').replace('/', '_').replace(':', '_')}.html"
        html_file_path = nebula.base_path / html_filename
        args.extend(["-o", str(html_file_path)])
    
    # 构建完整命令
    cmd = [str(nebula.exe_path)] + args
    if "-w" not in args:
        cmd.extend(["-w", str(nebula.web_fingerprint_path)])
    if "-s" not in args:
        cmd.extend(["-s", str(nebula.service_fingerprint_path)])
    
    debug_info = []
    debug_info.append("=== 调试信息 ===")
    debug_info.append(f"工作目录: {nebula.base_path}")
    debug_info.append(f"可执行文件: {nebula.exe_path}")
    debug_info.append(f"Web指纹库: {nebula.web_fingerprint_path}")
    debug_info.append(f"服务指纹库: {nebula.service_fingerprint_path}")
    debug_info.append(f"完整命令: {' '.join(cmd)}")
    if html_file_path:
        debug_info.append(f"HTML输出路径: {html_file_path}")
    debug_info.append("")
    
    result = await nebula.run_nebula_finger(args)
    
    debug_info.append("=== 执行结果 ===")
    debug_info.append(f"返回码: {result['returncode']}")
    debug_info.append(f"成功: {result['success']}")
    debug_info.append("")
    
    debug_info.append("=== 标准输出 ===")
    debug_info.append(result.get('stdout', '(无输出)'))
    debug_info.append("")
    
    if result.get('stderr'):
        debug_info.append("=== 错误输出 ===")
        debug_info.append(result['stderr'])
        debug_info.append("")
    
    if html_file_path:
        await asyncio.sleep(1)
        debug_info.append("=== HTML文件检查 ===")
        debug_info.append(f"文件存在: {html_file_path.exists()}")
        if html_file_path.exists():
            try:
                size = html_file_path.stat().st_size
                debug_info.append(f"文件大小: {size} 字节")
            except Exception as e:
                debug_info.append(f"获取文件信息失败: {e}")
    
    return "\n".join(debug_info)

@mcp.tool()
async def scan_target(
    target: str,
    mode: str = "web",
    concurrent: int = 5,
    output_html: bool = False,
    silent: bool = False,
    no_favicon: bool = False,
    bp_stat: bool = False
) -> str:
    """
    扫描单个目标的指纹信息
    
    Args:
        target: 要扫描的目标 (例如: example.com 或 http://example.com)
        mode: 扫描模式，可选值: web, service, all (默认: web)
        concurrent: 并发数 (默认: 5)
        output_html: 是否生成HTML报告 (默认: False)
        silent: 静默模式，仅输出结果 (默认: False)
        no_favicon: 禁用Favicon检测 (默认: False)
        bp_stat: 只输出有指纹匹配的结果 (默认: False)
        
    Returns:
        扫描结果的字符串
    """
    args = ["-u", target, "-m", mode, "-c", str(concurrent)]
    
    if silent:
        args.append("-silent")
    if no_favicon:
        args.append("-no-favicon")
    if bp_stat:
        args.append("-BP-stat")
    
    # 如果需要HTML输出，指定HTML文件路径
    html_file_path = None
    if output_html:
        # 在NEBULAFINGER_PATH下生成HTML文件
        html_filename = f"nebula_scan_{target.replace('://', '_').replace('/', '_').replace(':', '_')}.html"
        html_file_path = nebula.base_path / html_filename
        args.extend(["-o", str(html_file_path)])
    
    result = await nebula.run_nebula_finger(args)
    
    if result["success"]:
        output = result["stdout"]
        if output_html and html_file_path:
            # 等待一下确保文件生成完成
            await asyncio.sleep(1)
            
            # 检查文件是否存在
            if html_file_path.exists():
                try:
                    with open(html_file_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    output += f"\n\n=== HTML 报告内容 ===\n{html_content}"
                    output += f"\n\nHTML 报告已保存至: {html_file_path}"
                except Exception as e:
                    output += f"\n\n读取HTML文件时出错: {e}"
            else:
                output += f"\n\n警告: HTML文件未生成 - {html_file_path}"
                output += f"\n命令执行: {result.get('command', 'N/A')}"
                if result.get('stderr'):
                    output += f"\n错误输出: {result['stderr']}"
        
        return output
    else:
        error_msg = f"扫描失败 (返回码: {result['returncode']})\n"
        if result.get("stderr"):
            error_msg += f"错误信息: {result['stderr']}\n"
        if result.get("error"):
            error_msg += f"异常信息: {result['error']}\n"
        return error_msg

@mcp.tool()
async def scan_targets_from_list(
    targets: List[str],
    mode: str = "web",
    concurrent: int = 5,
    output_html: bool = False,
    silent: bool = False,
    no_favicon: bool = False,
    bp_stat: bool = False
) -> str:
    """
    从目标列表扫描多个目标的指纹信息，要求传入目标列表，格式为：example1.com、example2.com、example3.com
    
    Args:
        targets: 要扫描的目标列表
        mode: 扫描模式，可选值: web, service, all (默认: web)
        concurrent: 并发数 (默认: 5)
        output_html: 是否生成HTML报告 (默认: False)
        silent: 静默模式，仅输出结果 (默认: False)
        no_favicon: 禁用Favicon检测 (默认: False)
        bp_stat: 只输出有指纹匹配的结果 (默认: False)
        
    Returns:
        扫描结果的字符串
    """
    # 创建临时文件保存目标列表
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8')
    try:
        for target in targets:
            temp_file.write(f"{target}\n")
        temp_file.close()
        
        args = ["-f", temp_file.name, "-m", mode, "-c", str(concurrent)]
        
        if silent:
            args.append("-silent")
        if no_favicon:
            args.append("-no-favicon")
        if bp_stat:
            args.append("-BP-stat")
        
        # 如果需要HTML输出，指定HTML文件路径
        html_file_path = None
        if output_html:
            # 在NEBULAFINGER_PATH下生成HTML文件
            html_filename = f"nebula_scan_batch_{len(targets)}_targets.html"
            html_file_path = nebula.base_path / html_filename
            args.extend(["-o", str(html_file_path)])
        
        result = await nebula.run_nebula_finger(args)
        
        if result["success"]:
            output = result["stdout"]
            if output_html and html_file_path:
                # 等待一下确保文件生成完成
                await asyncio.sleep(1)
                
                # 检查文件是否存在
                if html_file_path.exists():
                    try:
                        with open(html_file_path, 'r', encoding='utf-8') as f:
                            html_content = f.read()
                        output += f"\n\n=== HTML 报告内容 ===\n{html_content}"
                        output += f"\n\nHTML 报告已保存至: {html_file_path}"
                    except Exception as e:
                        output += f"\n\n读取HTML文件时出错: {e}"
                else:
                    output += f"\n\n警告: HTML文件未生成 - {html_file_path}"
                    output += f"\n命令执行: {result.get('command', 'N/A')}"
                    if result.get('stderr'):
                        output += f"\n错误输出: {result['stderr']}"
            
            return output
        else:
            error_msg = f"扫描失败 (返回码: {result['returncode']})\n"
            if result.get("stderr"):
                error_msg += f"错误信息: {result['stderr']}\n"
            if result.get("error"):
                error_msg += f"异常信息: {result['error']}\n"
            return error_msg
            
    finally:
        # 清理临时文件
        try:
            os.unlink(temp_file.name)
        except:
            pass

@mcp.tool()
async def scan_targets_from_file(
    file_path: str,
    mode: str = "web",
    concurrent: int = 5,
    output_html: bool = False,
    silent: bool = False,
    no_favicon: bool = False,
    bp_stat: bool = False
) -> str:
    """
    从文件读取目标列表进行扫描
    
    Args:
        file_path: 包含目标列表的文件路径 (绝对路径或相对路径)
        mode: 扫描模式，可选值: web, service, all (默认: web)
        concurrent: 并发数 (默认: 5)
        output_html: 是否生成HTML报告 (默认: False)
        silent: 静默模式，仅输出结果 (默认: False)
        no_favicon: 禁用Favicon检测 (默认: False)
        bp_stat: 只输出有指纹匹配的结果 (默认: False)
        
    Returns:
        扫描结果的字符串
    """
    # 处理文件路径 - 支持相对路径和绝对路径
    input_file = Path(file_path)
    if not input_file.is_absolute():
        # 如果是相对路径，尝试相对于工作目录
        input_file = nebula.base_path / file_path
    
    # 确保文件存在
    if not input_file.exists():
        # 如果还是不存在，尝试原始路径
        input_file = Path(file_path)
        if not input_file.exists():
            return f"错误: 文件不存在 - {file_path}\n尝试的路径:\n- {nebula.base_path / file_path}\n- {file_path}"
    
    # 读取文件内容进行验证
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f if line.strip()]
        logger.info(f"从文件 {input_file} 读取到 {len(targets)} 个目标")
    except Exception as e:
        return f"错误: 无法读取文件 {input_file} - {e}"
    
    args = ["-f", str(input_file), "-m", mode, "-c", str(concurrent)]
    
    if silent:
        args.append("-silent")
    if no_favicon:
        args.append("-no-favicon")
    if bp_stat:
        args.append("-BP-stat")
    
    # 如果需要HTML输出，指定HTML文件路径
    html_file_path = None
    if output_html:
        # 在NEBULAFINGER_PATH下生成HTML文件，使用输入文件名作为基础
        html_filename = f"nebula_scan_file_{input_file.stem}_{int(time.time())}.html"
        html_file_path = nebula.base_path / html_filename
        args.extend(["-o", str(html_file_path)])
    
    # 添加调试信息
    debug_info = f"=== 扫描文件参数 ===\n"
    debug_info += f"输入文件: {input_file}\n"
    debug_info += f"目标数量: {len(targets)}\n"
    debug_info += f"扫描模式: {mode}\n"
    debug_info += f"并发数: {concurrent}\n"
    if html_file_path:
        debug_info += f"HTML输出: {html_file_path}\n"
    debug_info += f"完整命令参数: {args}\n\n"
    
    result = await nebula.run_nebula_finger(args)
    
    output = debug_info
    
    if result["success"]:
        output += f"=== 扫描结果 ===\n{result['stdout']}\n"
        
        if output_html and html_file_path:
            # 等待一下确保文件生成完成
            await asyncio.sleep(2)
            
            # 检查文件是否存在
            if html_file_path.exists():
                try:
                    with open(html_file_path, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    output += f"\n=== HTML 报告内容 ===\n{html_content}"
                    output += f"\n\nHTML 报告已保存至: {html_file_path}"
                except Exception as e:
                    output += f"\n\n读取HTML文件时出错: {e}"
            else:
                output += f"\n\n警告: HTML文件未生成 - {html_file_path}"
                output += f"\n命令执行: {result.get('command', 'N/A')}"
                if result.get('stderr'):
                    output += f"\n错误输出: {result['stderr']}"
        
        return output
    else:
        error_msg = f"扫描失败 (返回码: {result['returncode']})\n"
        if result.get("stderr"):
            error_msg += f"错误信息: {result['stderr']}\n"
        if result.get("error"):
            error_msg += f"异常信息: {result['error']}\n"
        error_msg += f"执行的命令: {result.get('command', 'N/A')}\n"
        return output + error_msg

@mcp.tool()
async def get_help() -> str:
    """
    获取 NebulaFinger 工具的帮助信息
    
    Returns:
        帮助信息字符串
    """
    result = await nebula.run_nebula_finger(["-h"])
    
    if result["success"]:
        return result["stdout"]
    else:
        return f"获取帮助信息失败: {result.get('stderr', result.get('error', '未知错误'))}"

@mcp.tool()
async def get_version() -> str:
    """
    获取 NebulaFinger 工具的版本信息
    
    Returns:
        版本信息字符串
    """
    # 尝试获取版本信息
    result = await nebula.run_nebula_finger(["--version"])
    
    if result["success"]:
        return result["stdout"]
    else:
        # 如果没有 --version 参数，返回基本信息
        return f"NebulaFinger - Web与服务指纹识别工具\n路径: {nebula.exe_path}\n配置目录: {nebula.configs_path}"

@mcp.tool()
async def check_status() -> str:
    """
    检查 NebulaFinger 工具的状态和配置
    
    Returns:
        状态信息字符串
    """
    status_info = []
    
    # 检查可执行文件
    status_info.append(f"可执行文件: {nebula.exe_path}")
    status_info.append(f"  - 存在: {'是' if nebula.exe_path.exists() else '否'}")
    
    # 检查配置目录
    status_info.append(f"配置目录: {nebula.configs_path}")
    status_info.append(f"  - 存在: {'是' if nebula.configs_path.exists() else '否'}")
    
    # 检查指纹库文件
    fingerprint_files = [
        ("Web指纹库", nebula.web_fingerprint_path),
        ("服务指纹库", nebula.service_fingerprint_path),
        ("权重配置", nebula.configs_path / "fingerprint_weights.json"),
        ("端口配置", nebula.configs_path / "tcp_ports.json")
    ]
    
    for name, path in fingerprint_files:
        status_info.append(f"{name}: {path}")
        status_info.append(f"  - 存在: {'是' if path.exists() else '否'}")
        if path.exists():
            try:
                size = path.stat().st_size
                status_info.append(f"  - 大小: {size} 字节")
            except:
                status_info.append("  - 大小: 无法获取")
    
    return "\n".join(status_info)

if __name__ == "__main__":
    # 启动 MCP 服务器
    mcp.run()