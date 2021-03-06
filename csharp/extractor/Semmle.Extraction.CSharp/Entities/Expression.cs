using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Semmle.Extraction.CSharp.Populators;
using Semmle.Extraction.Entities;
using Semmle.Extraction.Kinds;
using System.Linq;

namespace Semmle.Extraction.CSharp.Entities
{
    public interface IExpressionParentEntity : IEntity
    {
        /// <summary>
        /// Whether this entity is the parent of a top-level expression.
        /// </summary>
        bool IsTopLevelParent { get; }
    }

    class Expression : FreshEntity, IExpressionParentEntity
    {
        public readonly Type Type;
        public readonly Extraction.Entities.Location Location;
        public readonly ExprKind Kind;

        internal Expression(IExpressionInfo info)
            : base(info.Context)
        {
            Location = info.Location;
            Kind = info.Kind;
            Type = info.Type ?? NullType.Create(cx);

            cx.Emit(Tuples.expressions(this, Kind, Type.TypeRef));
            if (info.Parent.IsTopLevelParent)
                cx.Emit(Tuples.expr_parent_top_level(this, info.Child, info.Parent));
            else
                cx.Emit(Tuples.expr_parent(this, info.Child, info.Parent));
            cx.Emit(Tuples.expr_location(this, Location));

            if (info.IsCompilerGenerated)
                cx.Emit(Tuples.expr_compiler_generated(this));

            if (info.ExprValue is string value)
                cx.Emit(Tuples.expr_value(this, value));

            Type.ExtractGenerics();
        }

        public override Microsoft.CodeAnalysis.Location ReportingLocation => Location.symbol;

        bool IExpressionParentEntity.IsTopLevelParent => false;

        /// <summary>
        /// Gets a string represention of a constant value.
        /// </summary>
        /// <param name="obj">The value.</param>
        /// <returns>The string representation.</returns>
        public static string ValueAsString(object value)
        {
            return value == null ? "null" : value is bool ? ((bool)value ? "true" : "false") : value.ToString();
        }

        /// <summary>
        /// Creates an expression from a syntax node.
        /// Inserts type conversion as required.
        /// </summary>
        /// <param name="cx">The extraction context.</param>
        /// <param name="node">The node to extract.</param>
        /// <param name="parent">The parent entity.</param>
        /// <param name="child">The child index.</param>
        /// <param name="type">A type hint.</param>
        /// <returns>The new expression.</returns>
        public static Expression Create(Context cx, ExpressionSyntax node, IExpressionParentEntity parent, int child) =>
            CreateFromNode(new ExpressionNodeInfo(cx, node, parent, child));

        public static Expression CreateFromNode(ExpressionNodeInfo info) => Expressions.ImplicitCast.Create(info);

        /// <summary>
        /// Creates an expression from a syntax node.
        /// Inserts type conversion as required.
        /// Population is deferred to avoid overflowing the stack.
        /// </summary>
        /// <param name="cx">The extraction context.</param>
        /// <param name="node">The node to extract.</param>
        /// <param name="parent">The parent entity.</param>
        /// <param name="child">The child index.</param>
        /// <param name="type">A type hint.</param>
        public static void CreateDeferred(Context cx, ExpressionSyntax node, IExpressionParentEntity parent, int child)
        {
            if (ContainsPattern(node))
                // Expressions with patterns should be created right away, as they may introduce
                // local variables referenced in `LocalVariable::GetAlreadyCreated()`
                Create(cx, node, parent, child);
            else
                cx.PopulateLater(() => Create(cx, node, parent, child));
        }

        static bool ContainsPattern(SyntaxNode node) =>
            node is PatternSyntax || node is VariableDesignationSyntax || node.ChildNodes().Any(ContainsPattern);

        /// <summary>
        /// Adapt the operator kind depending on whether it's a dynamic call or a user-operator call.
        /// </summary>
        /// <param name="cx"></param>
        /// <param name="node"></param>
        /// <param name="originalKind"></param>
        /// <returns></returns>
        public static ExprKind UnaryOperatorKind(Context cx, ExprKind originalKind, ExpressionSyntax node) =>
            GetCallType(cx, node).AdjustKind(originalKind);

        /// <summary>
        /// If the expression calls an operator, add an expr_call()
        /// to show the target of the call. Also note the dynamic method
        /// name if available.
        /// </summary>
        /// <param name="cx">Context</param>
        /// <param name="node">The expression.</param>
        public void OperatorCall(ExpressionSyntax node)
        {
            var @operator = cx.GetSymbolInfo(node);
            if (@operator.Symbol is IMethodSymbol method)
            {

                var callType = GetCallType(cx, node);
                if (callType == CallType.Dynamic)
                {
                    UserOperator.OperatorSymbol(method.Name, out string operatorName);
                    cx.Emit(Tuples.dynamic_member_name(this, operatorName));
                    return;
                }

                cx.Emit(Tuples.expr_call(this, Method.Create(cx, method)));
            }
        }

        public enum CallType
        {
            None,
            BuiltInOperator,
            Dynamic,
            UserOperator
        }

        /// <summary>
        /// Determine what type of method was called for this expression.
        /// </summary>
        /// <param name="cx">The context.</param>
        /// <param name="node">The expression</param>
        /// <returns>The call type.</returns>
        public static CallType GetCallType(Context cx, ExpressionSyntax node)
        {
            var @operator = cx.GetSymbolInfo(node);

            if (@operator.Symbol is IMethodSymbol method)
            {
                if (method.ContainingSymbol is ITypeSymbol containingSymbol && containingSymbol.TypeKind == Microsoft.CodeAnalysis.TypeKind.Dynamic)
                {
                    return CallType.Dynamic;
                }

                switch (method.MethodKind)
                {
                    case MethodKind.BuiltinOperator:
                        if (method.ContainingType != null && method.ContainingType.TypeKind == Microsoft.CodeAnalysis.TypeKind.Delegate)
                            return CallType.UserOperator;
                        return CallType.BuiltInOperator;
                    case MethodKind.Constructor:
                        // The index operator ^... generates a constructor call to System.Index.
                        // Instead, treat this as a regular operator.
                        return CallType.None;
                    default:
                        return CallType.UserOperator;
                }
            }

            return CallType.None;
        }


        public static bool IsDynamic(Context cx, ExpressionSyntax node)
        {
            var ti = cx.GetTypeInfo(node).ConvertedType;
            return ti != null && ti.TypeKind == Microsoft.CodeAnalysis.TypeKind.Dynamic;
        }

        /// <summary>
        /// Given b in a?.b.c, return a.
        /// </summary>
        /// <param name="node">A MemberBindingExpression.</param>
        /// <returns>The qualifier of the conditional access.</returns>
        protected static ExpressionSyntax FindConditionalQualifier(ExpressionSyntax node)
        {
            for (SyntaxNode n = node; n != null; n = n.Parent)
            {
                var conditionalAccess = n.Parent as ConditionalAccessExpressionSyntax;

                if (conditionalAccess != null && conditionalAccess.WhenNotNull == n)
                    return conditionalAccess.Expression;
            }

            throw new InternalError(node, "Unable to locate a ConditionalAccessExpression");
        }

        public void MakeConditional()
        {
            cx.Emit(Tuples.conditional_access(this));
        }

        public void PopulateArguments(BaseArgumentListSyntax args, int child)
        {
            foreach (var arg in args.Arguments)
                PopulateArgument(arg, child++);
        }

        private void PopulateArgument(ArgumentSyntax arg, int child)
        {
            var expr = Create(cx, arg.Expression, this, child);
            int mode;
            switch (arg.RefOrOutKeyword.Kind())
            {
                case SyntaxKind.RefKeyword:
                    mode = 1;
                    break;
                case SyntaxKind.OutKeyword:
                    mode = 2;
                    break;
                case SyntaxKind.None:
                    mode = 0;
                    break;
                case SyntaxKind.InKeyword:
                    mode = 3;
                    break;
                default:
                    throw new InternalError(arg, "Unknown argument type");
            }
            cx.Emit(Tuples.expr_argument(expr, mode));

            if (arg.NameColon != null)
            {
                cx.Emit(Tuples.expr_argument_name(expr, arg.NameColon.Name.Identifier.Text));
            }
        }

        public override string ToString() => Label.ToString();

        public override TrapStackBehaviour TrapStackBehaviour => TrapStackBehaviour.OptionalLabel;
    }

    static class CallTypeExtensions
    {
        /// <summary>
        /// Adjust the expression kind <paramref name="k"/> to match this call type.
        /// </summary>
        public static ExprKind AdjustKind(this Expression.CallType ct, ExprKind k)
        {
            switch (ct)
            {
                case Expression.CallType.Dynamic:
                case Expression.CallType.UserOperator:
                    return ExprKind.OPERATOR_INVOCATION;
                default:
                    return k;
            }
        }
    }

    abstract class Expression<SyntaxNode> : Expression
        where SyntaxNode : ExpressionSyntax
    {
        public readonly SyntaxNode Syntax;

        protected Expression(ExpressionNodeInfo info)
            : base(info)
        {
            Syntax = (SyntaxNode)info.Node;
        }

        /// <summary>
        /// Populates expression-type specific relations in the trap file. The general relations
        /// <code>expressions</code> and <code>expr_location</code> are populated by the constructor
        /// (should not fail), so even if expression-type specific population fails (e.g., in
        /// standalone extraction), the expression created via
        /// <see cref="Expression.Create(Context, ExpressionSyntax, IEntity, int, ITypeSymbol)"/> will
        /// still be valid.
        /// </summary>
        protected abstract void Populate();

        protected Expression TryPopulate()
        {
            cx.Try(Syntax, null, Populate);
            return this;
        }
    }

    /// <summary>
    /// Holds all information required to create an Expression entity.
    /// </summary>
    interface IExpressionInfo
    {
        Context Context { get; }

        /// <summary>
        /// The type of the expression.
        /// </summary>
        Type Type { get; }

        /// <summary>
        /// The location of the expression.
        /// </summary>
        Extraction.Entities.Location Location { get; }

        /// <summary>
        /// The kind of the expression.
        /// </summary>
        ExprKind Kind { get; }

        /// <summary>
        /// The parent of the expression.
        /// </summary>
        IExpressionParentEntity Parent { get; }

        /// <summary>
        /// The child index of the expression.
        /// </summary>
        int Child { get; }

        /// <summary>
        /// Holds if this is an implicit expression.
        /// </summary>
        bool IsCompilerGenerated { get; }

        /// <summary>
        /// Gets a string representation of the value.
        /// null is encoded as the string "null".
        /// If the expression does not have a value, then this
        /// is null.
        /// </summary>
        string ExprValue { get; }
    }

    /// <summary>
    /// Explicitly constructed expression information.
    /// </summary>
    class ExpressionInfo : IExpressionInfo
    {
        public Context Context { get; }
        public Type Type { get; }
        public Extraction.Entities.Location Location { get; }
        public ExprKind Kind { get; }
        public IExpressionParentEntity Parent { get; }
        public int Child { get; }
        public bool IsCompilerGenerated { get; }
        public string ExprValue { get; }

        public ExpressionInfo(Context cx, Type type, Extraction.Entities.Location location, ExprKind kind, IExpressionParentEntity parent, int child, bool isCompilerGenerated, string value)
        {
            Context = cx;
            Type = type;
            Location = location;
            Kind = kind;
            Parent = parent;
            Child = child;
            ExprValue = value;
            IsCompilerGenerated = isCompilerGenerated;
        }
    }

    /// <summary>
    /// Expression information constructed from a syntax node.
    /// </summary>
    class ExpressionNodeInfo : IExpressionInfo
    {
        public ExpressionNodeInfo(Context cx, ExpressionSyntax node, IExpressionParentEntity parent, int child) :
            this(cx, node, parent, child, cx.GetTypeInfo(node))
        {
        }

        public ExpressionNodeInfo(Context cx, ExpressionSyntax node, IExpressionParentEntity parent, int child, TypeInfo typeInfo)
        {
            Context = cx;
            Node = node;
            Parent = parent;
            Child = child;
            TypeInfo = typeInfo;
            Conversion = cx.Model(node).GetConversion(node);
        }

        public ExpressionNodeInfo(Context cx, ExpressionSyntax node, IExpressionParentEntity parent, int child, ITypeSymbol type) :
            this(cx, node, parent, child)
        {
            Type = Type.Create(cx, type);
        }

        public Context Context { get; }
        public ExpressionSyntax Node { get; private set; }
        public IExpressionParentEntity Parent { get; set; }
        public int Child { get; set; }
        public TypeInfo TypeInfo { get; }
        public Microsoft.CodeAnalysis.CSharp.Conversion Conversion { get; }

        public ITypeSymbol ResolvedType => Context.DisambiguateType(TypeInfo.Type);
        public ITypeSymbol ConvertedType => Context.DisambiguateType(TypeInfo.ConvertedType);

        public ITypeSymbol ExpressionType
        {
            get
            {
                var type = ResolvedType;

                if (type == null)
                    type = Context.DisambiguateType(TypeInfo.Type ?? TypeInfo.ConvertedType);

                // Roslyn workaround: It can't work out the type of "new object[0]"
                // Clearly a bug.
                if (type != null && type.TypeKind == Microsoft.CodeAnalysis.TypeKind.Error)
                {
                    var arrayCreation = Node as ArrayCreationExpressionSyntax;
                    if (arrayCreation != null)
                    {
                        var elementType = Context.GetType(arrayCreation.Type.ElementType);

                        if (elementType != null)
                            return Context.Compilation.CreateArrayTypeSymbol(elementType, arrayCreation.Type.RankSpecifiers.Count);
                    }

                    Context.ModelError(Node, "Failed to determine type");
                }

                return type;
            }
        }

        Microsoft.CodeAnalysis.Location location;

        public Microsoft.CodeAnalysis.Location CodeAnalysisLocation
        {
            get
            {
                if (location == null)
                    location = Node.FixedLocation();
                return location;
            }
            set
            {
                location = value;
            }
        }

        public SemanticModel Model => Context.Model(Node);

        public string ExprValue
        {
            get
            {
                var c = Model.GetConstantValue(Node);
                return c.HasValue ? Expression.ValueAsString(c.Value) : null;
            }
        }

        Type cachedType;

        public Type Type
        {
            get
            {
                if (cachedType == null)
                    cachedType = Type.Create(Context, ExpressionType);
                return cachedType;
            }
            set
            {
                cachedType = value;
            }
        }

        Extraction.Entities.Location cachedLocation;

        public Extraction.Entities.Location Location
        {
            get
            {
                if (cachedLocation == null)
                    cachedLocation = Context.Create(CodeAnalysisLocation);
                return cachedLocation;
            }

            set
            {
                cachedLocation = value;
            }
        }

        public ExprKind Kind { get; set; } = ExprKind.UNKNOWN;

        public bool IsCompilerGenerated { get; set; }

        public ExpressionNodeInfo SetParent(IExpressionParentEntity parent, int child)
        {
            Parent = parent;
            Child = child;
            return this;
        }

        public ExpressionNodeInfo SetKind(ExprKind kind)
        {
            Kind = kind;
            return this;
        }

        public ExpressionNodeInfo SetType(Type type)
        {
            Type = type;
            return this;
        }

        public ExpressionNodeInfo SetNode(ExpressionSyntax node)
        {
            Node = node;
            return this;
        }

        SymbolInfo cachedSymbolInfo;

        public SymbolInfo SymbolInfo
        {
            get
            {
                if (cachedSymbolInfo.Symbol == null && cachedSymbolInfo.CandidateReason == CandidateReason.None)
                    cachedSymbolInfo = Model.GetSymbolInfo(Node);
                return cachedSymbolInfo;
            }
        }
    }
}
