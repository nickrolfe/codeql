/**
 * @name Use of dangerous function
 * @description Use of a standard library function that does not guard against buffer overflow.
 * @kind problem
 * @problem.severity error
 * @precision very-high
 * @id cpp/dangerous-function-overflow
 * @tags reliability
 *       security
 *       external/cwe/cwe-242
 */
import cpp

from FunctionCall call, Function target
where
  call.getTarget() = target and
  target.hasGlobalName("gets")
select call, "gets does not guard against buffer overflow"
