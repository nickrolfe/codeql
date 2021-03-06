/**
 * @name String concatenation in loop
 * @description Concatenating strings in loops has quadratic performance.
 * @kind problem
 * @tags efficiency
 *       maintainability
 * @problem.severity recommendation
 * @sub-severity low
 * @precision low
 * @id py/string-concatenation-in-loop
 */

import python

predicate string_concat_in_loop(BinaryExpr b) {
    b.getOp() instanceof Add
    and
    exists(SsaVariable d, SsaVariable u, BinaryExprNode add, ClassObject str_type |
           add.getNode() = b and d = u.getAnUltimateDefinition() |
           d.getDefinition().(DefinitionNode).getValue() = add and u.getAUse() = add.getAnOperand() and
           add.getAnOperand().refersTo(_, str_type, _) and
           (str_type = theBytesType() or str_type = theUnicodeType())
    )
}


from BinaryExpr b, Stmt s
where string_concat_in_loop(b) and s.getASubExpression() = b
select s, "String concatenation in a loop is quadratic in the number of iterations."
