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

MODULE := module/pna.ko
USER := user/user_message

all: $(MODULE) $(USER)
	$(MAKE) -C monitors/ BASE=$(PWD)
	$(MAKE) -C contrib/ BASE=$(PWD)

$(MODULE):
	$(MAKE) -C module/

$(USER):
	$(MAKE) -C user/

start: $(MODULE) $(USER)
	./service/pna start "$(PARMS)"

stop:
	./service/pna stop

dumper:
	./service/pna load pna_dumper

status:
	./service/pna status

clean:
	$(MAKE) -C module/ clean
	$(MAKE) -C user/ clean
	$(MAKE) -C monitors/ clean
	$(MAKE) -C contrib/ clean

realclean: clean
	rm -f irq_count.start irq_count.stop
	rm -f user_message.log
