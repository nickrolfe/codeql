using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Linq;

namespace Semmle.Extraction.CSharp.Entities
{
    class UserOperator : Method
    {
        protected UserOperator(Context cx, IMethodSymbol init)
            : base(cx, init) { }

        public override void Populate()
        {
            PopulateMethod();
            ExtractModifiers();

            var returnType = Type.Create(Context, symbol.ReturnType);
            Context.Emit(Tuples.operators(this,
                symbol.Name,
                OperatorSymbol(Context, symbol.Name),
                ContainingType,
                returnType.TypeRef,
                (UserOperator)OriginalDefinition));

            foreach (var l in Locations)
                Context.Emit(Tuples.operator_location(this, l));

            if (IsSourceDeclaration)
            {
                var declSyntaxReferences = symbol.DeclaringSyntaxReferences.Select(s => s.GetSyntax()).ToArray();
                foreach (var declaration in declSyntaxReferences.OfType<OperatorDeclarationSyntax>())
                    TypeMention.Create(Context, declaration.ReturnType, this, returnType);
                foreach (var declaration in declSyntaxReferences.OfType<ConversionOperatorDeclarationSyntax>())
                    TypeMention.Create(Context, declaration.Type, this, returnType);
            }

            ContainingType.ExtractGenerics();
        }

        public override bool NeedsPopulation => Context.Defines(symbol) || IsImplicitOperator(out _);

        public override Type ContainingType
        {
            get
            {
                IsImplicitOperator(out var containingType);
                return Type.Create(Context, containingType);
            }
        }

        public override IId Id
        {
            get
            {
                return new Key(tb =>
                {
                    AddSignatureTypeToId(Context, tb, symbol, symbol.ReturnType); // Needed for op_explicit(), which differs only by return type.
                    tb.Append(" ");
                    BuildMethodId(this, tb);
                });
            }
        }

        /// <summary>
        /// For some reason, some operators are missing from the Roslyn database of mscorlib.
        /// This method returns <code>true</code> for such operators.
        /// </summary>
        /// <param name="containingType">The type containing this operator.</param>
        /// <returns></returns>
        bool IsImplicitOperator(out ITypeSymbol containingType)
        {
            containingType = symbol.ContainingType;
            if (containingType != null)
            {
                var containingNamedType = containingType as INamedTypeSymbol;
                return containingNamedType == null || !containingNamedType.MemberNames.Contains(symbol.Name);
            }

            var pointerType = symbol.Parameters.Select(p => p.Type).OfType<IPointerTypeSymbol>().FirstOrDefault();
            if (pointerType != null)
            {
                containingType = pointerType;
                return true;
            }

            Context.ModelError(symbol, "Unexpected implicit operator");
            return true;
        }

        /// <summary>
        /// Convert an operator method name in to a symbolic name.
        /// A return value indicates whether the conversion succeeded.
        /// </summary>
        /// <param name="methodName">The method name.</param>
        /// <param name="operatorName">The converted operator name.</param>
        public static bool OperatorSymbol(string methodName, out string operatorName)
        {
            var success = true;
            switch (methodName)
            {
                case "op_LogicalNot":
                    operatorName = "!";
                    break;
                case "op_BitwiseAnd":
                    operatorName = "&";
                    break;
                case "op_Equality":
                    operatorName = "==";
                    break;
                case "op_Inequality":
                    operatorName = "!=";
                    break;
                case "op_UnaryPlus":
                case "op_Addition":
                    operatorName = "+";
                    break;
                case "op_UnaryNegation":
                case "op_Subtraction":
                    operatorName = "-";
                    break;
                case "op_Multiply":
                    operatorName = "*";
                    break;
                case "op_Division":
                    operatorName = "/";
                    break;
                case "op_Modulus":
                    operatorName = "%";
                    break;
                case "op_GreaterThan":
                    operatorName = ">";
                    break;
                case "op_GreaterThanOrEqual":
                    operatorName = ">=";
                    break;
                case "op_LessThan":
                    operatorName = "<";
                    break;
                case "op_LessThanOrEqual":
                    operatorName = "<=";
                    break;
                case "op_Decrement":
                    operatorName = "--";
                    break;
                case "op_Increment":
                    operatorName = "++";
                    break;
                case "op_Implicit":
                    operatorName = "implicit conversion";
                    break;
                case "op_Explicit":
                    operatorName = "explicit conversion";
                    break;
                case "op_OnesComplement":
                    operatorName = "~";
                    break;
                case "op_RightShift":
                    operatorName = ">>";
                    break;
                case "op_LeftShift":
                    operatorName = "<<";
                    break;
                case "op_BitwiseOr":
                    operatorName = "|";
                    break;
                case "op_ExclusiveOr":
                    operatorName = "^";
                    break;
                case "op_True":
                    operatorName = "true";
                    break;
                case "op_False":
                    operatorName = "false";
                    break;
                default:
                    operatorName = methodName;
                    success = false;
                    break;
            }
            return success;
        }

        /// <summary>
        /// Converts a method name into a symbolic name.
        /// Logs an error if the name is not found.
        /// </summary>
        /// <param name="cx">Extractor context.</param>
        /// <param name="methodName">The method name.</param>
        /// <returns>The converted name.</returns>
        public static string OperatorSymbol(Context cx, string methodName)
        {
            string result;
            if (!OperatorSymbol(methodName, out result))
                cx.ModelError($"Unhandled operator name in OperatorSymbol(): '{methodName}'");
            return result;
        }

        public new static UserOperator Create(Context cx, IMethodSymbol symbol) => UserOperatorFactory.Instance.CreateEntity(cx, symbol);

        class UserOperatorFactory : ICachedEntityFactory<IMethodSymbol, UserOperator>
        {
            public static readonly UserOperatorFactory Instance = new UserOperatorFactory();

            public UserOperator Create(Context cx, IMethodSymbol init) => new UserOperator(cx, init);
        }
    }
}
