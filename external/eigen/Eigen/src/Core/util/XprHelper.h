// Copyright (C) 2008 Gael Guennebaud <gael.guennebaud@inria.fr>
// Copyright (C) 2006-2008 Benoit Jacob <jacob.benoit.1@gmail.com>
// Public License v. 2.0. If a copy of the MPL was not distributed

#ifndef EIGEN_XPRHELPER_H
#define EIGEN_XPRHELPER_H

#if (defined __GNUG__) && !((__GNUC__==4) && (__GNUC_MINOR__==3))
  #define EIGEN_EMPTY_STRUCT_CTOR(X) \
    EIGEN_STRONG_INLINE X() {} \
    EIGEN_STRONG_INLINE X(const X& ) {}
#else
  #define EIGEN_EMPTY_STRUCT_CTOR(X)
#endif

namespace Eigen {

typedef EIGEN_DEFAULT_DENSE_INDEX_TYPE DenseIndex;

namespace internal {

class no_assignment_operator
{
  private:
    no_assignment_operator& operator=(const no_assignment_operator&);
};

template<typename I1, typename I2>
struct promote_index_type
{
  typedef typename conditional<(sizeof(I1)<sizeof(I2)), I2, I1>::type type;
};

template<typename T, int Value> class variable_if_dynamic
{
  public:
    EIGEN_EMPTY_STRUCT_CTOR(variable_if_dynamic)
    explicit variable_if_dynamic(T v) { EIGEN_ONLY_USED_FOR_DEBUG(v); assert(v == T(Value)); }
    static T value() { return T(Value); }
    void setValue(T) {}
};

template<typename T> class variable_if_dynamic<T, Dynamic>
{
    T m_value;
    variable_if_dynamic() { assert(false); }
  public:
    explicit variable_if_dynamic(T value) : m_value(value) {}
    T value() const { return m_value; }
    void setValue(T value) { m_value = value; }
};

template<typename T, int Value> class variable_if_dynamicindex
{
  public:
    EIGEN_EMPTY_STRUCT_CTOR(variable_if_dynamicindex)
    explicit variable_if_dynamicindex(T v) { EIGEN_ONLY_USED_FOR_DEBUG(v); assert(v == T(Value)); }
    static T value() { return T(Value); }
    void setValue(T) {}
};

template<typename T> class variable_if_dynamicindex<T, DynamicIndex>
{
    T m_value;
    variable_if_dynamicindex() { assert(false); }
  public:
    explicit variable_if_dynamicindex(T value) : m_value(value) {}
    T value() const { return m_value; }
    void setValue(T value) { m_value = value; }
};

template<typename T> struct functor_traits
{
  enum
  {
    Cost = 10,
    PacketAccess = false,
    IsRepeatable = false
  };
};

template<typename T> struct packet_traits;

template<typename T> struct unpacket_traits
{
  typedef T type;
  enum {size=1};
};

template<typename _Scalar, int _Rows, int _Cols,
         int _Options = AutoAlign |
                          ( (_Rows==1 && _Cols!=1) ? RowMajor
                          : (_Cols==1 && _Rows!=1) ? ColMajor
                          : EIGEN_DEFAULT_MATRIX_STORAGE_ORDER_OPTION ),
         int _MaxRows = _Rows,
         int _MaxCols = _Cols
> class make_proper_matrix_type
{
    enum {
      IsColVector = _Cols==1 && _Rows!=1,
      IsRowVector = _Rows==1 && _Cols!=1,
      Options = IsColVector ? (_Options | ColMajor) & ~RowMajor
              : IsRowVector ? (_Options | RowMajor) & ~ColMajor
              : _Options
    };
  public:
    typedef Matrix<_Scalar, _Rows, _Cols, Options, _MaxRows, _MaxCols> type;
};

template<typename Scalar, int Rows, int Cols, int Options, int MaxRows, int MaxCols>
class compute_matrix_flags
{
    enum {
      row_major_bit = Options&RowMajor ? RowMajorBit : 0,
      is_dynamic_size_storage = MaxRows==Dynamic || MaxCols==Dynamic,

      aligned_bit =
      (
            ((Options&DontAlign)==0)
        && (
#if EIGEN_ALIGN_STATICALLY
             ((!is_dynamic_size_storage) && (((MaxCols*MaxRows*int(sizeof(Scalar))) % 16) == 0))
#else
             0
#endif

          ||

#if EIGEN_ALIGN
             is_dynamic_size_storage
#else
             0
#endif

          )
      ) ? AlignedBit : 0,
      packet_access_bit = packet_traits<Scalar>::Vectorizable && aligned_bit ? PacketAccessBit : 0
    };

  public:
    enum { ret = LinearAccessBit | LvalueBit | DirectAccessBit | NestByRefBit | packet_access_bit | row_major_bit | aligned_bit };
};

template<int _Rows, int _Cols> struct size_at_compile_time
{
  enum { ret = (_Rows==Dynamic || _Cols==Dynamic) ? Dynamic : _Rows * _Cols };
};


template<typename T, typename StorageKind = typename traits<T>::StorageKind> struct plain_matrix_type;
template<typename T, typename BaseClassType> struct plain_matrix_type_dense;
template<typename T> struct plain_matrix_type<T,Dense>
{
  typedef typename plain_matrix_type_dense<T,typename traits<T>::XprKind>::type type;
};

template<typename T> struct plain_matrix_type_dense<T,MatrixXpr>
{
  typedef Matrix<typename traits<T>::Scalar,
                traits<T>::RowsAtCompileTime,
                traits<T>::ColsAtCompileTime,
                AutoAlign | (traits<T>::Flags&RowMajorBit ? RowMajor : ColMajor),
                traits<T>::MaxRowsAtCompileTime,
                traits<T>::MaxColsAtCompileTime
          > type;
};

template<typename T> struct plain_matrix_type_dense<T,ArrayXpr>
{
  typedef Array<typename traits<T>::Scalar,
                traits<T>::RowsAtCompileTime,
                traits<T>::ColsAtCompileTime,
                AutoAlign | (traits<T>::Flags&RowMajorBit ? RowMajor : ColMajor),
                traits<T>::MaxRowsAtCompileTime,
                traits<T>::MaxColsAtCompileTime
          > type;
};


template<typename T, typename StorageKind = typename traits<T>::StorageKind> struct eval;

template<typename T> struct eval<T,Dense>
{
  typedef typename plain_matrix_type<T>::type type;
};

template<typename _Scalar, int _Rows, int _Cols, int _Options, int _MaxRows, int _MaxCols>
struct eval<Matrix<_Scalar, _Rows, _Cols, _Options, _MaxRows, _MaxCols>, Dense>
{
  typedef const Matrix<_Scalar, _Rows, _Cols, _Options, _MaxRows, _MaxCols>& type;
};

template<typename _Scalar, int _Rows, int _Cols, int _Options, int _MaxRows, int _MaxCols>
struct eval<Array<_Scalar, _Rows, _Cols, _Options, _MaxRows, _MaxCols>, Dense>
{
  typedef const Array<_Scalar, _Rows, _Cols, _Options, _MaxRows, _MaxCols>& type;
};



template<typename T> struct plain_matrix_type_column_major
{
  enum { Rows = traits<T>::RowsAtCompileTime,
         Cols = traits<T>::ColsAtCompileTime,
         MaxRows = traits<T>::MaxRowsAtCompileTime,
         MaxCols = traits<T>::MaxColsAtCompileTime
  };
  typedef Matrix<typename traits<T>::Scalar,
                Rows,
                Cols,
                (MaxRows==1&&MaxCols!=1) ? RowMajor : ColMajor,
                MaxRows,
                MaxCols
          > type;
};

template<typename T> struct plain_matrix_type_row_major
{
  enum { Rows = traits<T>::RowsAtCompileTime,
         Cols = traits<T>::ColsAtCompileTime,
         MaxRows = traits<T>::MaxRowsAtCompileTime,
         MaxCols = traits<T>::MaxColsAtCompileTime
  };
  typedef Matrix<typename traits<T>::Scalar,
                Rows,
                Cols,
                (MaxCols==1&&MaxRows!=1) ? RowMajor : ColMajor,
                MaxRows,
                MaxCols
          > type;
};

template<typename T> struct must_nest_by_value { enum { ret = false }; };

template <typename T>
struct ref_selector
{
  typedef typename conditional<
    bool(traits<T>::Flags & NestByRefBit),
    T const&,
    const T
  >::type type;
};

template<typename T1, typename T2>
struct transfer_constness
{
  typedef typename conditional<
    bool(internal::is_const<T1>::value),
    typename internal::add_const_on_value_type<T2>::type,
    T2
  >::type type;
};

template<typename T, int n=1, typename PlainObject = typename eval<T>::type> struct nested
{
  enum {
    
    
    
    
    
    DynamicAsInteger = 10000,
    ScalarReadCost = NumTraits<typename traits<T>::Scalar>::ReadCost,
    ScalarReadCostAsInteger = ScalarReadCost == Dynamic ? int(DynamicAsInteger) : int(ScalarReadCost),
    CoeffReadCost = traits<T>::CoeffReadCost,
    CoeffReadCostAsInteger = CoeffReadCost == Dynamic ? int(DynamicAsInteger) : int(CoeffReadCost),
    NAsInteger = n == Dynamic ? int(DynamicAsInteger) : n,
    CostEvalAsInteger   = (NAsInteger+1) * ScalarReadCostAsInteger + CoeffReadCostAsInteger,
    CostNoEvalAsInteger = NAsInteger * CoeffReadCostAsInteger
  };

  typedef typename conditional<
      ( (int(traits<T>::Flags) & EvalBeforeNestingBit) ||
        int(CostEvalAsInteger) < int(CostNoEvalAsInteger)
      ),
      PlainObject,
      typename ref_selector<T>::type
  >::type type;
};

template<typename T>
inline T* const_cast_ptr(const T* ptr)
{
  return const_cast<T*>(ptr);
}

template<typename Derived, typename XprKind = typename traits<Derived>::XprKind>
struct dense_xpr_base
{
  
};

template<typename Derived>
struct dense_xpr_base<Derived, MatrixXpr>
{
  typedef MatrixBase<Derived> type;
};

template<typename Derived>
struct dense_xpr_base<Derived, ArrayXpr>
{
  typedef ArrayBase<Derived> type;
};

template<typename Derived,typename Scalar,typename OtherScalar,
         bool EnableIt = !is_same<Scalar,OtherScalar>::value >
struct special_scalar_op_base : public DenseCoeffsBase<Derived>
{
  
  
  void operator*() const;
};

template<typename Derived,typename Scalar,typename OtherScalar>
struct special_scalar_op_base<Derived,Scalar,OtherScalar,true>  : public DenseCoeffsBase<Derived>
{
  const CwiseUnaryOp<scalar_multiple2_op<Scalar,OtherScalar>, Derived>
  operator*(const OtherScalar& scalar) const
  {
    return CwiseUnaryOp<scalar_multiple2_op<Scalar,OtherScalar>, Derived>
      (*static_cast<const Derived*>(this), scalar_multiple2_op<Scalar,OtherScalar>(scalar));
  }

  inline friend const CwiseUnaryOp<scalar_multiple2_op<Scalar,OtherScalar>, Derived>
  operator*(const OtherScalar& scalar, const Derived& matrix)
  { return static_cast<const special_scalar_op_base&>(matrix).operator*(scalar); }
};

template<typename XprType, typename CastType> struct cast_return_type
{
  typedef typename XprType::Scalar CurrentScalarType;
  typedef typename remove_all<CastType>::type _CastType;
  typedef typename _CastType::Scalar NewScalarType;
  typedef typename conditional<is_same<CurrentScalarType,NewScalarType>::value,
                              const XprType&,CastType>::type type;
};

template <typename A, typename B> struct promote_storage_type;

template <typename A> struct promote_storage_type<A,A>
{
  typedef A ret;
};

template<typename ExpressionType, typename Scalar = typename ExpressionType::Scalar>
struct plain_row_type
{
  typedef Matrix<Scalar, 1, ExpressionType::ColsAtCompileTime,
                 ExpressionType::PlainObject::Options | RowMajor, 1, ExpressionType::MaxColsAtCompileTime> MatrixRowType;
  typedef Array<Scalar, 1, ExpressionType::ColsAtCompileTime,
                 ExpressionType::PlainObject::Options | RowMajor, 1, ExpressionType::MaxColsAtCompileTime> ArrayRowType;

  typedef typename conditional<
    is_same< typename traits<ExpressionType>::XprKind, MatrixXpr >::value,
    MatrixRowType,
    ArrayRowType 
  >::type type;
};

template<typename ExpressionType, typename Scalar = typename ExpressionType::Scalar>
struct plain_col_type
{
  typedef Matrix<Scalar, ExpressionType::RowsAtCompileTime, 1,
                 ExpressionType::PlainObject::Options & ~RowMajor, ExpressionType::MaxRowsAtCompileTime, 1> MatrixColType;
  typedef Array<Scalar, ExpressionType::RowsAtCompileTime, 1,
                 ExpressionType::PlainObject::Options & ~RowMajor, ExpressionType::MaxRowsAtCompileTime, 1> ArrayColType;

  typedef typename conditional<
    is_same< typename traits<ExpressionType>::XprKind, MatrixXpr >::value,
    MatrixColType,
    ArrayColType 
  >::type type;
};

template<typename ExpressionType, typename Scalar = typename ExpressionType::Scalar>
struct plain_diag_type
{
  enum { diag_size = EIGEN_SIZE_MIN_PREFER_DYNAMIC(ExpressionType::RowsAtCompileTime, ExpressionType::ColsAtCompileTime),
         max_diag_size = EIGEN_SIZE_MIN_PREFER_FIXED(ExpressionType::MaxRowsAtCompileTime, ExpressionType::MaxColsAtCompileTime)
  };
  typedef Matrix<Scalar, diag_size, 1, ExpressionType::PlainObject::Options & ~RowMajor, max_diag_size, 1> MatrixDiagType;
  typedef Array<Scalar, diag_size, 1, ExpressionType::PlainObject::Options & ~RowMajor, max_diag_size, 1> ArrayDiagType;

  typedef typename conditional<
    is_same< typename traits<ExpressionType>::XprKind, MatrixXpr >::value,
    MatrixDiagType,
    ArrayDiagType 
  >::type type;
};

template<typename ExpressionType>
struct is_lvalue
{
  enum { value = !bool(is_const<ExpressionType>::value) &&
                 bool(traits<ExpressionType>::Flags & LvalueBit) };
};

} 

} 

#endif 
