/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ebpf

// Event actions
const (
	EventActionAllow uint8 = 0
	EventActionBlock uint8 = 1
	EventActionAudit uint8 = 2
)

// Event phases
const (
	EventPhaseInitialization uint8 = 0
	EventPhaseLearning       uint8 = 1
	EventPhaseEnforcing      uint8 = 2
)

// Network directions
const (
	NetworkDirectionInbound  uint8 = 0
	NetworkDirectionOutbound uint8 = 1
)

// File operations (based on common syscalls)
const (
	FileOperationOpen   uint32 = 2  // sys_open
	FileOperationRead   uint32 = 0  // sys_read
	FileOperationWrite  uint32 = 1  // sys_write
	FileOperationClose  uint32 = 3  // sys_close
	FileOperationUnlink uint32 = 87 // sys_unlink
	FileOperationMkdir  uint32 = 83 // sys_mkdir
	FileOperationRmdir  uint32 = 84 // sys_rmdir
)
