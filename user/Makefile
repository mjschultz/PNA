# Copyright 2011 Washington University in St Louis
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Any user created monitors should go on this line
user-deps := pna.o

# standard user-space programs
progs := user_message
prog-deps := pna_message.o session_dump.o proc_dump.o

config := load_nets
config-deps :=

CFLAGS += -I../include/
LDLIBS := -lpthread -lpcap

all: $(progs) $(config)

debug: CFLAGS += -ggdb
debug: $(progs)

$(progs): $(prog-deps)

$(config): $(config-deps)

contrib: $(user-deps)
	make -C ../contrib

clean:
	rm -f $(progs) $(prog-deps) $(config) $(config-deps)
	rm -f $(special-progs) $(special-deps) $(user-progs) $(user-deps)
