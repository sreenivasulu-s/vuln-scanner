import asyncio
import signal
import os
import shutil
from dataclasses import dataclass


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class ToolRunner:
    """Safe subprocess runner for locally installed security tools."""

    async def run(
        self,
        tool: str,
        args: list[str],
        *,
        timeout: float = 60.0,
        stdin_data: str | None = None,
    ) -> ToolResult:
        command = [tool, *args]

        if os.getenv("VULN_SCANNER_DISABLE_EXTERNAL_TOOLS") == "1":
            return ToolResult(
                tool=tool,
                command=command,
                returncode=0,
                stdout="",
                stderr="",
            )

        executable = shutil.which(tool)

        if not executable:
            return ToolResult(
                tool=tool,
                command=command,
                returncode=127,
                stdout="",
                stderr=f"{tool} is not installed or is not in PATH",
            )

        command = [executable, *args]

        try:
            print(f"[ToolRunner] START {tool}", flush=True)

            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )

            print(
                f"[ToolRunner] PID {process.pid} STARTED {tool}",
                flush=True,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(
                        input=(
                            stdin_data.encode()
                            if stdin_data is not None
                            else None
                        )
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                print(
                    f"[ToolRunner] TIMEOUT {tool} after {timeout}s",
                    flush=True,
                )

                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

                # Never allow timeout cleanup itself to hang the scan.
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=2.0,
                    )
                except (asyncio.TimeoutError, ProcessLookupError):
                    stdout, stderr = b"", b""

                print(
                    f"[ToolRunner] TIMEOUT CLEANUP COMPLETE {tool}",
                    flush=True,
                )

                return ToolResult(
                    tool=tool,
                    command=command,
                    returncode=124,
                    stdout=stdout.decode(errors="replace"),
                    stderr=(
                        stderr.decode(errors="replace")
                        or f"timeout after {timeout}s"
                    ),
                    timed_out=True,
                )

            print(
                f"[ToolRunner] DONE {tool} rc={process.returncode}",
                flush=True,
            )

            return ToolResult(
                tool=tool,
                command=command,
                returncode=process.returncode or 0,
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
            )

        except OSError as exc:
            return ToolResult(
                tool=tool,
                command=command,
                returncode=126,
                stdout="",
                stderr=str(exc),
            )
