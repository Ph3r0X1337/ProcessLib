This Library contains the classes LocalProcess and ExtProcess, which are both inherited from the IProcess abstract class.

LocalProcess
This class can be used to access specific information about the current Process such as loaded Modules, 
but it also offers a Wow64 process to call 64-bit functions such as NTAPI or custom 64-bit functions of your choice, 
therefore extending the capabilities of a Wow64 process to those of a regular native process.

ExtProcess
This class can be used to access other processes on the system, regardless of their bitness and the bitness of your code. 
The ExtProcess class uses the LocalProcess Singleton to gain access to functions, that can be used to query other processes on the system.

IProcess
This abstract class can be used as an interface for both child classes, to access common functions that both children share.

The goal of this library is to make access to other processes easy and provide a modular interface that looks the same in all possible scenarios,
but should also provide you with the capability of executing 64-bit code in Wow64 processes.
