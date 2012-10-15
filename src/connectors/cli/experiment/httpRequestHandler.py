"""HTTP request handler example.

The following partial example shows how HTTP requests can be read with
async_chat. A web server might create an http_request_handler object for each
incoming client connection. Notice that initially the channel terminator is set
to match the blank line at the end of the HTTP headers, and a flag indicates
that the headers are being read.

Once the headers have been read, if the request is of type POST (indicating that
further data are present in the input stream) then the Content-Length: header is
used to set a numeric terminator to read the right amount of data from the
channel.

The handle_request() method is called once all relevant input has been
marshalled, after setting the channel terminator to None to ensure that any
extraneous data sent by the web client are ignored.

"""

import socket
import asyncore
import asynchat

class http_request_handler(asynchat.async_chat):

    def __init__(self, sock, addr, sessions, log):
        asynchat.async_chat.__init__(self, sock=sock)
        self.addr = addr
        self.sessions = sessions
        self.ibuffer = []
        self.obuffer = ""
        self.set_terminator("\r\n\r\n")
        self.reading_headers = True
        self.handling = False
        self.cgi_data = None
        self.log = log

    def collect_incoming_data(self, data):
        """Buffer the data"""
        self.ibuffer.append(data)

    def found_terminator(self):
        if self.reading_headers:
            self.reading_headers = False
            self.parse_headers("".join(self.ibuffer))
            self.ibuffer = []
            if self.op.upper() == "POST":
                clen = self.headers.getheader("content-length")
                self.set_terminator(int(clen))
            else:
                self.handling = True
                self.set_terminator(None)
                self.handle_request()
        elif not self.handling:
            self.set_terminator(None) # browsers sometimes over-send
            self.cgi_data = parse(self.headers, "".join(self.ibuffer))
            self.handling = True
            self.ibuffer = []
            self.handle_request()

    # obvious

    def handle_request(self):
        print(self.cgi_data)
        self.cgi_data = None
        self.headers = []

    # extraneous

    def parse_headers(self, data):
        self.headers += "".join(self.ibuffer)


class http_request_server(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            print("Incoming connection from %s" % repr(addr))
            handler = http_request_handler(sock, addr, None, None)

def main():
    server = http_request_server('localhost', 8080)
    asyncore.loop()

if __name__ == "__main__":
    main()
