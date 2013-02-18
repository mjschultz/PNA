/**
 * Copyright 2011 Washington University in St Louis
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* PNA configuration values */

#include "pna_module.h"

/* configuration parameters */
char *pna_iface = "none";
uint pna_session_entries = (1 << 21); /* 2,097,152      */
uint pna_tables = 2;
bool pna_debug = false;
bool pna_perfmon = true;
bool pna_session_mon = true;

PNA_PARAM(charp, pna_iface, "Interface on which we listen to packets");
PNA_PARAM(uint, pna_session_entries, "Number of session entries per dump period");
PNA_PARAM(uint, pna_tables, "Number of <src,dst,port> tables to use");
PNA_PARAM(bool, pna_debug, "Enable kernel debug log messages");
PNA_PARAM(bool, pna_perfmon, "Enable PNA performance monitoring messages");
PNA_PARAM(bool, pna_session_mon, "Enable PNA session monitoring");

