/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "lkconsole_ca.h"
#include "lkconsole_ca_ipc.h"
#include <cutils/log.h>

#define LINE_LEN 128

const uint32_t SEND_BUF_SIZE = 2048;
const uint32_t RECV_BUF_SIZE = 2048;
static char buffer[LINE_LEN] = {0};

int read_debug_line_ca(const char **outbuffer);

int main()
{
	uint32_t command = TA_START;
	uint8_t recv_buf[RECV_BUF_SIZE];
	uint32_t response_size = RECV_BUF_SIZE;
	uint8_t send_buf[SEND_BUF_SIZE];
	uint32_t request_size = SEND_BUF_SIZE;
	const char* buff = NULL ;
	int rc ;

	if(handle_ == 0) {
		rc = trusty_lkconsole_connect();
		if (rc < 0) {
			printf("Error initializing lkconsole session: %d\n", rc);
			return ERROR_UNKNOWN;
		}
	}

	command = TA_START ;

	while(1){
		printf("lk# ");
		memset(send_buf,0,SEND_BUF_SIZE);
		memset(recv_buf,0,RECV_BUF_SIZE);
		read_debug_line_ca(&buff) ;
		if(buff[0] == 0) {
			continue ;
		}

		memcpy(send_buf,buff , SEND_BUF_SIZE);
		response_size = RECV_BUF_SIZE ;

		if(memcmp("exit",buff,sizeof("exit"))==0) {
			break ;
		}

		rc = trusty_lkconsole_call(command, send_buf, request_size, recv_buf, &response_size);
		if (rc < 0) {
			printf("error (%d) calling  TA\n", rc);
			return rc;
		}

		struct lkconsole_message *msg = (struct lkconsole_message *)recv_buf;
		uint8_t *payload = msg->payload;

		printf("\n%s\n", payload);
	}

	trusty_lkconsole_disconnect();
	return 0;
}

/* echo commands? */
static int echo = 0;

int read_debug_line_ca(const char **outbuffer)
{
	int pos = 0;
	int escape_level = 0;

	for (;;) {
		/* loop until we get a char */
		int c;
		if ((c = getchar()) < 0)
			continue;

		if (escape_level == 0) {
			switch (c) {
				case '\r':
				case '\n':
					if (echo)
						putchar('\n');
					goto done;

				case 0x7f: // backspace or delete
				case 0x8:
					if (pos > 0) {
						pos--;
						fputc('\b', stdout);
						putchar(' ');
						fputc('\b', stdout); // move to the left one
					}
					break;

				case 0x1b: // escape
					escape_level++;
					break;

				default:
					buffer[pos++] = c;
					if (echo)
						putchar(c);
			}
		}else if (escape_level == 1) {
			// inside an escape, look for '['
			if (c == '[') {
				escape_level++;
			} else {
				// we didn't get it, abort
				escape_level = 0;
			}
		} else { // escape_level > 1
			switch (c) {
				case 67: // right arrow
					buffer[pos++] = ' ';
					if (echo)
						putchar(' ');
					break;
				case 68: // left arrow
					if (pos > 0) {
						pos--;
						if (echo) {
							fputc('\b', stdout); // move to the left one
							putchar(' ');
							fputc('\b', stdout); // move to the left one
						}
					}
					break;
#if CONSOLE_ENABLE_HISTORY
				case 65: // up arrow -- previous history
				case 66: // down arrow -- next history
					// wipe out the current line
					while (pos > 0) {
						pos--;
						if (echo) {
							fputc('\b', stdout); // move to the left one
							putchar(' ');
							fputc('\b', stdout); // move to the left one
						}
					}
					pos = strlen(buffer);
					if (echo)
						fputs(buffer, stdout);
					break;
#endif
				default:
					break;
			}
			escape_level = 0;
		}

		/* end of line. */
		if (pos == (LINE_LEN - 1)) {
			fputs("\nerror: line too long\n", stdout);
			pos = 0;
			goto done;
		}
	}

done:
	// null terminate
	buffer[pos] = 0;

	// return a pointer to our buffer
	*outbuffer = buffer;
	return pos;
}
