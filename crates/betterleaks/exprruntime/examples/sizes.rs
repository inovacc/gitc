fn main() {
    println!("Value       = {}", std::mem::size_of::<exprruntime::Value>());
    println!("EvalError   = {}", std::mem::size_of::<exprruntime::EvalError>());
    println!("Result<V,E> = {}", std::mem::size_of::<Result<exprruntime::Value, exprruntime::EvalError>>());
}
