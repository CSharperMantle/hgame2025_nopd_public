# Nop'd

HGAME 2025 Reverse Engineering challenge

**Difficulty:** Week 4 Hard

> Don't want to make up excuses and embarrass everyone when your private "homework" collection is accidentally discovered? Try our latest **Nondestructive Opaque Protection & Deniability&trade;** (Nop'd&trade;) technology! Feel free to give up `game` to interrogators, and it will run like any normal, old-fashioned adventure game. Only via our special `launcher` can the real content be unlocked...
> 
> **Backup attachment link**: <https://1drv.ms/u/c/a62edaf3b21e7091/EUtPwkiYcpJFozGMGpY3bK0BaIzyFIqXmE-6qScbgcYepg?e=uI4sau> (valid before 2024/02/25)

## Build

```sh
xmake config --mode=challenge
xmake
```

## Exploit

Solution recipe in [CyberChef](https://github.com/gchq/CyberChef/): <https://gchq.github.io/CyberChef/#recipe=From_Hex('None')XOR(%7B'option':'Hex','string':'46'%7D,'Input%20differential',false)ChaCha(%7B'option':'UTF8','string':'It%5C's%20all%20written%20in%20the%20Book%20of%20'%7D,%7B'option':'UTF8','string':'What%5C's%20your%20'%7D,0,'20','Raw','Raw')&input=NjQ2QTUwMTc4MTdENkYxQTg3QjFBNDAwMDkwM0Y4OERGODZCREYzMjVGNDA5MDlDQjgzRDg2MTMyNkI3NjNGNzc0RTg1M0VENTgyMDRGRDk5OTI2MjEzN0RFMzU3NkM4QkNEMDZF>

## License

Copyright &copy; 2025, Rong "Mantle" Bao <<webmaster@csmantle.top>>.

Copyright &copy; 2025, Vidar-Team <<public@vidar.club>>.

Redistribution in source and binary forms, with or without modification, is prohibited without the prior written consent from the Copyright Holders and Contributors.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
