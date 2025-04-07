use core::fmt;
use std::{error, fmt::LowerHex, fs::File, io::BufReader};
use byteorder::{ReadBytesExt, BigEndian};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::util::modified_utf8_to_string;

// const READER_BUF_SIZE: usize = 8192;

const MAGIC: u32 = 0xCAFEBABE;

trait Tag {
    const TAG: u8;
}

trait PossibleTags {
    const TAGS: &'static Vec<u8>;
}

#[derive(EnumIter, Clone, Copy, Debug)]
pub enum MethodHandleReferenceKind {
    GetField = 1,
    GetStatic = 2,
    PutField = 3,
    PutStatic = 4,
    InvokeVirtual = 5,
    InvokeStatic = 6,
    InvokeSpecial = 7,
    NewInvokeSpecial = 8,
    InvokeInterface = 9
}

impl TryFrom<u8> for MethodHandleReferenceKind {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == MethodHandleReferenceKind::GetField as u8 => Ok(MethodHandleReferenceKind::GetField),
            x if x == MethodHandleReferenceKind::GetStatic as u8 => Ok(MethodHandleReferenceKind::GetStatic),
            x if x == MethodHandleReferenceKind::PutField as u8 => Ok(MethodHandleReferenceKind::PutField),
            x if x == MethodHandleReferenceKind::PutStatic as u8 => Ok(MethodHandleReferenceKind::PutStatic),
            x if x == MethodHandleReferenceKind::InvokeVirtual as u8 => Ok(MethodHandleReferenceKind::InvokeVirtual),
            x if x == MethodHandleReferenceKind::InvokeStatic as u8 => Ok(MethodHandleReferenceKind::InvokeStatic),
            x if x == MethodHandleReferenceKind::InvokeSpecial as u8 => Ok(MethodHandleReferenceKind::InvokeSpecial),
            x if x == MethodHandleReferenceKind::NewInvokeSpecial as u8 => Ok(MethodHandleReferenceKind::NewInvokeSpecial),
            x if x == MethodHandleReferenceKind::InvokeInterface as u8 => Ok(MethodHandleReferenceKind::InvokeInterface),
            _ => Err(()),
        }
    }
}

pub enum ClassAccessFlagMask {
    Public = 0x0001,
    Final = 0x0010,
    Super = 0x0020,
    Interface = 0x0200,
    Abstract = 0x0400,
    Synthetic = 0x1000,
    Annotation = 0x2000,
    Enum = 0x4000,
    Module = 0x8000,
}

pub enum MethodAccessFlagMask {
    Public = 0x0001,
    Private = 0x0002,
    Protected = 0x0004,
    Static = 0x0008,
    Final = 0x0010,
    Synchronized = 0x0020,
    Bridge = 0x0040,
    VarArgs = 0x0080,
    Native = 0x0100,
    Abstract = 0x0400,
    Strict = 0x8000,
    Synthetic = 0x1000,
}

pub enum InnerClassAccessFlagMask {
    Public = 0x0001,
    Private = 0x0002,
    Protected = 0x0004,
    Static = 0x0008,
    Final = 0x0010,
    Interface = 0x0200,
    Abstract = 0x0400,
    Synthetic = 0x1000,
    Annotation = 0x2000,
    Enum = 0x4000,
}

/** https://docs.oracle.com/javase/specs/jvms/se22/html/jvms-4.html */
#[derive(Debug)]
pub struct ClassFile {
    pub magic: u32,
    pub minor_version: u16,
    pub major_version: u16,
    pub constant_pool_count: u16,
    pub constant_pool: Vec<CpInfo>,
    pub access_flags: u16,
    pub this_class: u16,
    pub super_class: u16,
    // interfaces_count: u16,
    pub interfaces: Vec<u16>,
    // fields_count: u16,
    pub fields: Vec<FieldInfo>,
    // methods_count: u16,
    pub methods: Vec<MethodInfo>,
    // attributes_count: u16,
    pub attributes: Vec<AttributeInfo>
}

#[derive(Debug)]
pub enum CpInfo {
    Utf8(CpUtf8),
    Integer(CpInteger),
    Float(CpFloat),
    Long(CpLong),
    Double(CpDouble),
    Class(CpClass),
    String(CpString),
    FieldRef(CpFieldRef),
    MethodRef(CpMethodRef),
    InterfaceMethodRef(CpInterfaceMethodRef),
    NameAndType(CpNameAndType),
    MethodHandle(CpMethodHandle),
    MethodType(CpMethodType),
    Dynamic(CpDynamic),
    InvokeDynamic(CpInvokeDynamic),
    Module(CpModule),
    Package(CpPackage)
}

#[derive(Debug)]
pub struct CpUtf8 {
    // length: u16,
    /** Shranjeno v modified UTF-8 (glej https://docs.oracle.com/javase/specs/jvms/se22/html/jvms-4.html#jvms-4.4.7) */
    pub bytes: Vec<u8>,
    pub converted: String,
}

impl Tag for CpUtf8 {
    const TAG: u8 = 1;
}

#[derive(Debug)]
pub struct CpInteger {
    pub bytes: [u8; 4]
}

impl Tag for CpInteger {
    const TAG: u8 = 3;
}

#[derive(Debug)]
pub struct CpFloat {
    pub bytes: [u8; 4]
}

impl Tag for CpFloat {
    const TAG: u8 = 4;
}

#[derive(Debug)]
pub struct CpLong {
    pub high_bytes: u32,
    pub low_bytes: u32
}

impl Tag for CpLong {
    const TAG: u8 = 5;
}

#[derive(Debug)]
pub struct CpDouble {
    pub high_bytes: u32,
    pub low_bytes: u32
}

impl Tag for CpDouble {
    const TAG: u8 = 6;
}

#[derive(Debug)]
/** Class ali interface */
pub struct CpClass {
    pub name_index: u16
}

impl Tag for CpClass {
    const TAG: u8 = 7;
}

#[derive(Debug)]
pub struct CpString {
    pub string_index: u16
}

impl Tag for CpString {
    const TAG: u8 = 8;
}

#[derive(Debug)]
pub struct CpFieldRef {
    pub class_index: u16,
    pub name_and_type_index: u16
}

impl Tag for CpFieldRef {
    const TAG: u8 = 9;
}

#[derive(Debug)]
pub struct CpMethodRef {
    pub class_index: u16,
    pub name_and_type_index: u16
}

impl Tag for CpMethodRef {
    const TAG: u8 = 10;
}

#[derive(Debug)]
pub struct CpInterfaceMethodRef {
    pub class_index: u16,
    pub name_and_type_index: u16
}

impl Tag for CpInterfaceMethodRef {
    const TAG: u8 = 11;
}

#[derive(Debug)]
pub struct CpNameAndType {
    pub name_index: u16,
    pub descriptor_index: u16
}

impl Tag for CpNameAndType {
    const TAG: u8 = 12;
}

#[derive(Debug)]
pub struct CpMethodHandle {
    pub reference_kind: MethodHandleReferenceKind,
    pub reference_index: u16
}

impl Tag for CpMethodHandle {
    const TAG: u8 = 15;
}

#[derive(Debug)]
pub struct CpMethodType {
    pub descriptor_index: u16
}

impl Tag for CpMethodType {
    const TAG: u8 = 16;
}

#[derive(Debug)]
pub struct CpDynamic {
    pub bootstrap_method_attr_index: u16,
    pub name_and_type_index: u16
}

impl Tag for CpDynamic {
    const TAG: u8 = 17;
}

#[derive(Debug)]
pub struct CpInvokeDynamic {
    pub bootstrap_method_attr_index: u16,
    pub name_and_type_index: u16
}

impl Tag for CpInvokeDynamic {
    const TAG: u8 = 18;
}

#[derive(Debug)]
pub struct CpModule {
    pub name_index: u16
}

impl Tag for CpModule {
    const TAG: u8 = 19;
}

#[derive(Debug)]
pub struct CpPackage {
    pub name_index: u16
}

impl Tag for CpPackage {
    const TAG: u8 = 20;
}

#[derive(Debug)]
pub struct FieldInfo {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    // attributes_count: u16,
    pub attributes: Vec<AttributeInfo>
}

#[derive(Debug)]
pub struct MethodInfo {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    // attributes_count: u16,
    pub attributes: Vec<AttributeInfo>
}

#[derive(Debug)]
pub enum AttributeInfo {
    ConstantValue(AttributeConstantValue),
    Code(AttributeCode),
    StackMapTable(AttributeStackMapTable),
    Exceptions(AttributeExceptions),
    InnerClasses(AttributeInnerClasses),
    EnclosingMethod(AttributeEnclosingMethod),
    Synthetic(AttributeSynthetic),
    Signature(AttributeSignature),
    SourceFile(AttributeSourceFile),
    SourceDebugExtension(AttributeSourceDebugExtension),
    LineNumberTable(AttributeLineNumberTable),
    LocalVariableTable(AttributeLocalVariableTable),
    LocalVariableTypeTable(AttributeLocalVariableTypeTable),
    Deprecated(AttributeDeprecated),
    RuntimeVisibleAnnotations(AttributeRuntimeVisibleAnnotations),
    RuntimeInvisibleAnnotations(AttributeRuntimeInvisibleAnnotations),
    RuntimeVisibleParameterAnnotations(AttributeRuntimeVisibleParameterAnnotations),
    RuntimeInvisibleParameterAnnotations(AttributeRuntimeInvisibleParameterAnnotations),
    RuntimeVisibleTypeAnnotations(AttributeRuntimeVisibleTypeAnnotations),
    RuntimeInvisibleTypeAnnotations(AttributeRuntimeInvisibleTypeAnnotations),
    AnnotationDefault(AttributeAnnotationDefault),
    BootstrapMethods(AttributeBootstrapMethods),
    MethodParameters(AttributeMethodParameters),
    Module(AttributeModule),
    ModulePackages(AttributeModulePackages),
    ModuleMainClass(AttributeModuleMainClass),
    NestHost(AttributeNestHost),
    NestMembers(AttributeNestMembers),
    Record(AttributeRecord),
    PermittedSubclasses(AttributePermittedSubclasses),
}

trait AttributeName {
    const ATTRIBUTE_NAME: &'static str;
}

trait AttributeLength {
    const ATTRIBUTE_LENGTH: u32;
}

#[derive(Debug)]
pub struct AttributeConstantValue {
    pub constantvalue_index: u16
}

impl AttributeName for AttributeConstantValue {
    const ATTRIBUTE_NAME: &'static str = "ConstantValue";
}

#[derive(Debug)]
pub struct ExceptionTableEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: u16
}

#[derive(Debug)]
pub struct AttributeCode {
    pub attribute_length: u32,
    pub max_stack: u16,
    pub max_locals: u16,
    // code_length: u32,
    pub code: Vec<u8>,
    // exception_table_length: u16,
    pub exception_table: Vec<ExceptionTableEntry>,
    // attributes_count: u16,
    pub attributes: Vec<AttributeInfo>
}

impl AttributeName for AttributeCode {
    const ATTRIBUTE_NAME: &'static str = "Code";
}

#[derive(Debug)]
pub enum VerificationTypeInfo {
    TopVariable(VerificationTypeTopVariableInfo),
    IntegerVariable(VerificationTypeIntegerVariableInfo),
    FloatVariable(VerificationTypeFloatVariableInfo),
    NullVariable(VerificationTypeNullVariableInfo),
    UninitializedThisVariable(VerificationTypeUninitializedThisVariableInfo),
    ObjectVariable(VerificationTypeObjectVariableInfo),
    UninitializedVariable(VerificationTypeUninitializedVariableInfo),
    LongVariable(VerificationTypeLongVariableInfo),
    DoubleVariable(VerificationTypeDoubleVariableInfo),
}

#[derive(Debug)]
pub struct VerificationTypeTopVariableInfo {}

impl Tag for VerificationTypeTopVariableInfo {
    const TAG: u8 = 0;
}

#[derive(Debug)]
pub struct VerificationTypeIntegerVariableInfo {}

impl Tag for VerificationTypeIntegerVariableInfo {
    const TAG: u8 = 1;
}

#[derive(Debug)]
pub struct VerificationTypeFloatVariableInfo {}

impl Tag for VerificationTypeFloatVariableInfo {
    const TAG: u8 = 2;
}

#[derive(Debug)]
pub struct VerificationTypeNullVariableInfo {}

impl Tag for VerificationTypeNullVariableInfo {
    const TAG: u8 = 5;
}

#[derive(Debug)]
pub struct VerificationTypeUninitializedThisVariableInfo {}

impl Tag for VerificationTypeUninitializedThisVariableInfo {
    const TAG: u8 = 6;
}

#[derive(Debug)]
pub struct VerificationTypeObjectVariableInfo {
    pub cpool_index: u16,
}

impl Tag for VerificationTypeObjectVariableInfo {
    const TAG: u8 = 7;
}

#[derive(Debug)]
pub struct VerificationTypeUninitializedVariableInfo {
    pub offset: u16,
}

impl Tag for VerificationTypeUninitializedVariableInfo {
    const TAG: u8 = 8;
}

#[derive(Debug)]
pub struct VerificationTypeLongVariableInfo {}

impl Tag for VerificationTypeLongVariableInfo {
    const TAG: u8 = 4;
}

#[derive(Debug)]
pub struct VerificationTypeDoubleVariableInfo {}

impl Tag for VerificationTypeDoubleVariableInfo {
    const TAG: u8 = 3;
}

#[derive(Debug)]
pub enum StackMapFrame {
    SameFrame(StackMapSameFrame),
    SameLocals1StackItemFrame(StackMapSameLocals1StackItemFrame),
    SameLocals1StackItemFrameExtended(StackMapSameLocals1StackItemFrameExtended),
    ChopFrame(StackMapChopFrame),
    SameFrameExtended(StackMapSameFrameExtended),
    AppendFrame(StackMapAppendFrame),
    FullFrame(StackMapFullFrame),
}

trait TagRange {
    const TAG_LOWER: u8;
    const TAG_UPPER: u8;
}

#[derive(Debug)]
pub struct StackMapSameFrame {
    pub frame_type: u8,
}

impl TagRange for StackMapSameFrame {
    const TAG_LOWER: u8 = 0;
    const TAG_UPPER: u8 = 63;
}

#[derive(Debug)]
pub struct StackMapSameLocals1StackItemFrame {
    pub frame_type: u8,
    pub stack_entry: VerificationTypeInfo,
}

impl TagRange for StackMapSameLocals1StackItemFrame {
    const TAG_LOWER: u8 = 64;
    const TAG_UPPER: u8 = 127;
}

#[derive(Debug)]
pub struct StackMapSameLocals1StackItemFrameExtended {
    pub frame_type: u8,
    pub offset_delta: u16,
    pub stack_entry: VerificationTypeInfo,
}

impl Tag for StackMapSameLocals1StackItemFrameExtended {
    const TAG: u8 = 247;
}

#[derive(Debug)]
pub struct StackMapChopFrame {
    pub frame_type: u8,
    pub offset_delta: u16,
}

impl TagRange for StackMapChopFrame {
    const TAG_LOWER: u8 = 248;
    const TAG_UPPER: u8 = 250;
}

#[derive(Debug)]
pub struct StackMapSameFrameExtended  {
    pub frame_type: u8,
    pub offset_delta: u16,
}

impl Tag for StackMapSameFrameExtended {
    const TAG: u8 = 251;
}

#[derive(Debug)]
pub struct StackMapAppendFrame  {
    pub frame_type: u8,
    pub offset_delta: u16,
    pub locals: Vec<VerificationTypeInfo>,
}

impl TagRange for StackMapAppendFrame {
    const TAG_LOWER: u8 = 252;
    const TAG_UPPER: u8 = 254;
}

#[derive(Debug)]
pub struct StackMapFullFrame {
    pub frame_type: u8,
    pub offset_delta: u16,
    // number_of_locals: u16,
    pub locals: Vec<VerificationTypeInfo>,
    // number_of_stack_items: u16,
    pub stack: Vec<VerificationTypeInfo>,
}

impl Tag for StackMapFullFrame {
    const TAG: u8 = 255;
}

#[derive(Debug)]
pub struct AttributeStackMapTable {
    pub attribute_length: u32,
    // number_of_entries: u16,
    pub entries: Vec<StackMapFrame>
}

impl AttributeName for AttributeStackMapTable {
    const ATTRIBUTE_NAME: &'static str = "StackMapTable";
}

#[derive(Debug)]
pub struct AttributeExceptions {
    pub attribute_length: u32,
    // number_of_exceptions: u16,
    pub exception_index_table: Vec<u16>, 
}

impl AttributeName for AttributeExceptions {
    const ATTRIBUTE_NAME: &'static str = "Exceptions";
}

#[derive(Debug)]
pub struct AttributeInnerClassesClass {
    pub inner_class_info_index: u16,
    pub outer_class_info_index: u16,
    pub inner_name_index: u16,
    pub inner_class_access_flags: u16,
}

#[derive(Debug)]
pub struct AttributeInnerClasses {
    pub attribute_length: u32,
    // number_of_classes: u16,
    pub classes: Vec<AttributeInnerClassesClass>,
}

impl AttributeName for AttributeInnerClasses {
    const ATTRIBUTE_NAME: &'static str = "InnerClasses";
}

#[derive(Debug)]
pub struct AttributeEnclosingMethod {
    pub class_index: u16,
    pub method_index: u16,
}

impl AttributeName for AttributeEnclosingMethod {
    const ATTRIBUTE_NAME: &'static str = "EnclosingMethod";
}

impl AttributeLength for AttributeEnclosingMethod {
    const ATTRIBUTE_LENGTH: u32 = 4;
}

#[derive(Debug)]
pub struct AttributeSynthetic {}

impl AttributeName for AttributeSynthetic {
    const ATTRIBUTE_NAME: &'static str = "Synthetic";
}

impl AttributeLength for AttributeSynthetic {
    const ATTRIBUTE_LENGTH: u32 = 0;
}

#[derive(Debug)]
pub struct AttributeSignature {
    pub signature_index: u16,
}

impl AttributeName for AttributeSignature {
    const ATTRIBUTE_NAME: &'static str = "Signature";
}

impl AttributeLength for AttributeSignature {
    const ATTRIBUTE_LENGTH: u32 = 2;
}

#[derive(Debug)]
pub struct AttributeSourceFile {
    pub sourcefile_index: u16,
}

impl AttributeName for AttributeSourceFile {
    const ATTRIBUTE_NAME: &'static str = "SourceFile";
}

impl AttributeLength for AttributeSourceFile {
    const ATTRIBUTE_LENGTH: u32 = 2;
}

#[derive(Debug)]
pub struct AttributeSourceDebugExtension {
    // attribute_length: u32,
    pub debug_extension: Vec<u8>,
}

impl AttributeName for AttributeSourceDebugExtension {
    const ATTRIBUTE_NAME: &'static str = "SourceDebugExtension";
}

#[derive(Debug)]
pub struct AttributeLineNumberTableEntry {
    pub start_pc: u16,
    pub line_number: u16,
}

#[derive(Debug)]
pub struct AttributeLineNumberTable {
    pub attribute_length: u32,
    // line_number_table_length: u16,
    pub line_number_table: Vec<AttributeLineNumberTableEntry>,
}

impl AttributeName for AttributeLineNumberTable {
    const ATTRIBUTE_NAME: &'static str = "LineNumberTable";
}

#[derive(Debug)]
pub struct AttributeLocalVariableTableEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub index: u16,
}

#[derive(Debug)]
pub struct AttributeLocalVariableTable {
    pub attribute_length: u32,
    // local_variable_table_length: u16,
    pub local_variable_table: Vec<AttributeLocalVariableTableEntry>,
}

impl AttributeName for AttributeLocalVariableTable {
    const ATTRIBUTE_NAME: &'static str = "LocalVariableTable";
}

#[derive(Debug)]
pub struct AttributeLocalVariableTypeTableEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name_index: u16,
    pub signature_index: u16,
    pub index: u16,
}

#[derive(Debug)]
pub struct AttributeLocalVariableTypeTable {
    pub attribute_length: u32,
    // local_variable_table_length: u16,
    pub local_variable_table: Vec<AttributeLocalVariableTypeTableEntry>,
}

impl AttributeName for AttributeLocalVariableTypeTable {
    const ATTRIBUTE_NAME: &'static str = "LocalVariableTypeTableEntry";
}

#[derive(Debug)]
pub struct AttributeDeprecated {}

impl AttributeName for AttributeDeprecated {
    const ATTRIBUTE_NAME: &'static str = "Deprecated";
}

impl AttributeLength for AttributeDeprecated {
    const ATTRIBUTE_LENGTH: u32 = 0;
}

#[derive(Debug)]
pub enum AttributeAnnotationsElementValue {
    Byte(AttributeAnnotationsElementValueByte),
    Char(AttributeAnnotationsElementValueChar),
    Double(AttributeAnnotationsElementValueDouble),
    Float(AttributeAnnotationsElementValueFloat),
    Int(AttributeAnnotationsElementValueInt),
    Long(AttributeAnnotationsElementValueLong),
    Short(AttributeAnnotationsElementValueShort),
    Boolean(AttributeAnnotationsElementValueBoolean),
    String(AttributeAnnotationsElementValueString),
    EnumClass(AttributeAnnotationsElementValueEnumClass),
    Class(AttributeAnnotationsElementValueClass),
    AnnotationInterface(AttributeAnnotationsElementValueAnnotationInterface),
    ArrayType(AttributeAnnotationsElementValueArrayType),
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueByte {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueByte {
    const TAG: u8 = b'B';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueChar {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueChar {
    const TAG: u8 = b'C';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueDouble {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueDouble {
    const TAG: u8 = b'D';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueFloat {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueFloat {
    const TAG: u8 = b'F';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueInt {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueInt {
    const TAG: u8 = b'I';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueLong {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueLong {
    const TAG: u8 = b'J';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueShort {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueShort {
    const TAG: u8 = b'S';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueBoolean {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueBoolean {
    const TAG: u8 = b'Z';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueString {
    pub const_value_index: u16,
}

impl Tag for AttributeAnnotationsElementValueString {
    const TAG: u8 = b's';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueEnumClass {
    pub type_name_index: u16,
    pub const_name_index: u16,
}

impl Tag for AttributeAnnotationsElementValueEnumClass {
    const TAG: u8 = b'e';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueClass {
    pub class_info_index: u16,
}

impl Tag for AttributeAnnotationsElementValueClass {
    const TAG: u8 = b'c';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueAnnotationInterface {
    pub annotation_value: AttributeRuntimeAnnotationsEntry,
}

impl Tag for AttributeAnnotationsElementValueAnnotationInterface {
    const TAG: u8 = b'@';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValueArrayType {
    // num_values: u16,
    pub values: Vec<AttributeAnnotationsElementValue>,
}

impl Tag for AttributeAnnotationsElementValueArrayType {
    const TAG: u8 = b'[';
}

#[derive(Debug)]
pub struct AttributeAnnotationsElementValuePair {
    pub element_name_index: u16,
    pub element_value: AttributeAnnotationsElementValue
}

#[derive(Debug)]
pub struct AttributeRuntimeAnnotationsEntry {
    pub type_index: u16,
    // num_element_value_pairs: u16,
    pub element_value_pairs: Vec<AttributeAnnotationsElementValuePair>,
}

#[derive(Debug)]
pub struct AttributeRuntimeVisibleAnnotations {
    pub attribute_length: u32,
    // num_annotations: u16,
    pub annotations: Vec<AttributeRuntimeAnnotationsEntry>,
}

impl AttributeName for AttributeRuntimeVisibleAnnotations {
    const ATTRIBUTE_NAME: &'static str = "RuntimeVisibleAnnotations";
}

#[derive(Debug)]
pub struct AttributeRuntimeInvisibleAnnotations {
    pub attribute_length: u32,
    // num_annotations: u16,
    pub annotations: Vec<AttributeRuntimeAnnotationsEntry>,
}

impl AttributeName for AttributeRuntimeInvisibleAnnotations {
    const ATTRIBUTE_NAME: &'static str = "RuntimeInvisibleAnnotations";
}

#[derive(Debug)]
pub struct AttributeRuntimeVisibleParameterAnnotations {
    pub attribute_length: u32,
    // num_parameters: u8,
    pub parameter_annotations: Vec<Vec<AttributeRuntimeAnnotationsEntry>>,
}

impl AttributeName for AttributeRuntimeVisibleParameterAnnotations {
    const ATTRIBUTE_NAME: &'static str = "RuntimeVisibleParameterAnnotations";
}

#[derive(Debug)]
pub struct AttributeRuntimeInvisibleParameterAnnotations {
    pub attribute_length: u32,
    // num_parameters: u16,
    pub parameter_annotations: Vec<Vec<AttributeRuntimeAnnotationsEntry>>,
}

impl AttributeName for AttributeRuntimeInvisibleParameterAnnotations {
    const ATTRIBUTE_NAME: &'static str = "RuntimeInvisibleParameterAnnotations";
}

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryTypeParameterTarget {
    pub type_parameter_index: u8,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryTypeParameterTarget {
//     const TAGS: &'static Vec<u8> = [0x00, 0x01];
// }

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntrySuperTypeTarget {
    pub supertype_index: u16,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntrySuperTypeTarget {
//     const TAGS: Vec<u8> = [0x10].into();
// }

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryTypeParameterBoundTarget {
    pub type_parameter_index: u8,
    pub bound_index: u8,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryTypeParameterBoundTarget {
//     const TAGS: Vec<u8> = [0x11, 0x12].into();
// }

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryEmptyTarget {}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryEmptyTarget {
//     const TAGS: Vec<u8> = [0x13, 0x14, 0x15].into();
// }


#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryFormalParameterTarget {
    pub formal_parameter_index: u8,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryFormalParameterTarget {
//     const TAGS: Vec<u8> = [0x16].into();
// }

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryThrowsTarget {
    pub throws_type_index: u16,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryThrowsTarget {
//     const TAGS: Vec<u8> = [0x17].into();
// }

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryLocalvarTargetTableEntry {
    pub start_pc: u16,
    pub length: u16,
    pub index: u16,
}

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryLocalvarTarget {
    // table_length: u16,
    pub table: Vec<AttributeRuntimeTypeAnnotationsEntryLocalvarTargetTableEntry>,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryLocalvarTarget {
//     const TAGS: Vec<u8> = [0x40, 0x41].into();
// }

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryCatchTarget {
    pub exception_table_index: u16,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryCatchTarget {
//     const TAGS: Vec<u8> = [0x42].into();
// }

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryOffsetTarget {
    pub offset: u16,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryOffsetTarget {
//     const TAGS: Vec<u8> = [0x43, 0x44, 0x45, 0x46].into();
// }

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntryTypeArgumentTarget {
    pub offset: u16,
    pub type_argument_index: u8,
}

// impl PossibleTags for AttributeRuntimeTypeAnnotationsEntryTypeArgumentTarget {
//     const TAGS: Vec<u8> = [0x47, 0x48, 0x49, 0x4A, 0x4B].into();
// }

#[derive(Debug)]
pub enum AttributeRuntimeTypeAnnotationsEntryTargetInfo {
    TypeParameterTarget(AttributeRuntimeTypeAnnotationsEntryTypeParameterTarget),
    SuperTypeTarget(AttributeRuntimeTypeAnnotationsEntrySuperTypeTarget),
    TypeParameterBoundTarget(AttributeRuntimeTypeAnnotationsEntryTypeParameterBoundTarget),
    EmptyTarget(AttributeRuntimeTypeAnnotationsEntryEmptyTarget),
    FormalParameterTarget(AttributeRuntimeTypeAnnotationsEntryFormalParameterTarget),
    ThrowsTarget(AttributeRuntimeTypeAnnotationsEntryThrowsTarget),
    LocalvarTarget(AttributeRuntimeTypeAnnotationsEntryLocalvarTarget),
    CatchTarget(AttributeRuntimeTypeAnnotationsEntryCatchTarget),
    OffsetTarget(AttributeRuntimeTypeAnnotationsEntryOffsetTarget),
    TypeArgumentTarget(AttributeRuntimeTypeAnnotationsEntryTypeArgumentTarget),
}

#[derive(Debug)]
pub struct AttributeRuntimeVisibleTypeAnnotationsEntryTargetPathEntry {
    pub type_path_kind: u8,
    pub type_argument_index: u8,
}

#[derive(Debug)]
pub struct AttributeRuntimeTypeAnnotationsEntry {
    pub target_type: u8,
    pub target_info: AttributeRuntimeTypeAnnotationsEntryTargetInfo,
    // path_length: u8,
    pub target_path: Vec<AttributeRuntimeVisibleTypeAnnotationsEntryTargetPathEntry>,
    pub type_index: u16,
    // num_element_value_pairs: u16,
    pub element_value_pairs: Vec<AttributeAnnotationsElementValuePair>,
}

#[derive(Debug)]
pub struct AttributeRuntimeVisibleTypeAnnotations {
    pub attribute_length: u32,
    // num_annotations: u16,
    pub annotations: Vec<AttributeRuntimeTypeAnnotationsEntry>,
}

impl AttributeName for AttributeRuntimeVisibleTypeAnnotations {
    const ATTRIBUTE_NAME: &'static str = "RuntimeVisibleTypeAnnotations";
}

#[derive(Debug)]
pub struct AttributeRuntimeInvisibleTypeAnnotations {
    pub attribute_length: u32,
    // num_annotations: u16,
    pub annotations: Vec<AttributeRuntimeTypeAnnotationsEntry>,
}

impl AttributeName for AttributeRuntimeInvisibleTypeAnnotations {
    const ATTRIBUTE_NAME: &'static str = "RuntimeInvisibleTypeAnnotations";
}

#[derive(Debug)]
pub struct AttributeAnnotationDefault {
    pub attribute_length: u32,
    pub default_value: AttributeAnnotationsElementValue,
}

impl AttributeName for AttributeAnnotationDefault {
    const ATTRIBUTE_NAME: &'static str = "AnnotationDefault";
}

#[derive(Debug)]
pub struct AttributeBootstrapMethodsEntry {
    pub bootstrap_method_ref: u16,
    // num_bootstrap_arguments: u16,
    pub bootstrap_arguments: Vec<u16>
}

#[derive(Debug)]
pub struct AttributeBootstrapMethods {
    pub attribute_length: u32,
    // num_bootstrap_methods: u16,
    pub bootstrap_methods: Vec<AttributeBootstrapMethodsEntry>,
}

impl AttributeName for AttributeBootstrapMethods {
    const ATTRIBUTE_NAME: &'static str = "BootstrapMethods";
}

#[derive(Debug)]
pub struct AttributeMethodParametersEntry {
    pub name_index: u16,
    pub access_flags: u16,
}

#[derive(Debug)]
pub struct AttributeMethodParameters {
    pub attribute_length: u32,
    // parameters_count: u8,
    pub parameters: Vec<AttributeMethodParametersEntry>,
} 

impl AttributeName for AttributeMethodParameters {
    const ATTRIBUTE_NAME: &'static str = "MethodParameters";
}

#[derive(Debug)]
pub struct AttributeModuleRequiresEntry {
    pub requires_index: u16,
    pub requires_flags: u16,
    pub requires_version_index: u16,
}

#[derive(Debug)]
pub struct AttributeModuleExportsEntry {
    pub exports_index: u16,
    pub exports_flags: u16,
    // exports_to_count: u16,
    pub exports_to_index: Vec<u16>
}

#[derive(Debug)]
pub struct AttributeModuleOpensEntry {
    pub opens_index: u16,
    pub opens_flags: u16,
    // opens_to_count: u16,
    pub opens_to_index: Vec<u16>,
}

#[derive(Debug)]
pub struct AttributeModuleProvidesEntry {
    pub provides_index: u16,
    // provides_with_count: u16,
    pub provides_with_index: Vec<u16>,
}

#[derive(Debug)]
pub struct AttributeModule {
    pub attribute_length: u32,

    pub module_name_index: u16,
    pub module_flags: u16,
    pub module_version_index: u16,
    
    // requires_count: u16,
    pub requires: Vec<AttributeModuleRequiresEntry>,
    // exports_count: u16,
    pub exports: Vec<AttributeModuleExportsEntry>,
    // opens_count: u16,
    pub opens: Vec<AttributeModuleOpensEntry>,
    // uses_count: u16,
    pub uses_index: Vec<u16>,
    // provides_count: u16,
    pub provides: Vec<AttributeModuleProvidesEntry>,
}

impl AttributeName for AttributeModule {
    const ATTRIBUTE_NAME: &'static str = "Module";
}

#[derive(Debug)]
pub struct AttributeModulePackages {
    pub attribute_length: u32,
    // package_count: u16,
    pub package_index: Vec<u16>,
}

impl AttributeName for AttributeModulePackages {
    const ATTRIBUTE_NAME: &'static str = "ModulePackages";
}

#[derive(Debug)]
pub struct AttributeModuleMainClass {
    pub main_class_index: u16,
}

impl AttributeName for AttributeModuleMainClass {
    const ATTRIBUTE_NAME: &'static str = "ModuleMainClass";
}

impl AttributeLength for AttributeModuleMainClass {
    const ATTRIBUTE_LENGTH: u32 = 2;
}

#[derive(Debug)]
pub struct AttributeNestHost {
    pub host_class_index: u16,
}

impl AttributeName for AttributeNestHost {
    const ATTRIBUTE_NAME: &'static str = "NestHost";
}

impl AttributeLength for AttributeNestHost {
    const ATTRIBUTE_LENGTH: u32 = 2;
}

#[derive(Debug)]
pub struct AttributeNestMembers {
    pub attribute_length: u32,
    // number_of_classes: u16,
    pub classes: Vec<u16>,
}

impl AttributeName for AttributeNestMembers {
    const ATTRIBUTE_NAME: &'static str = "NestMembers";
}

#[derive(Debug)]
pub struct AttributeRecordComponentInfo {
    pub name_index: u16,
    pub descriptor_index: u16,
    // attributes_count: u16,
    pub attributes: Vec<AttributeInfo>,
}

#[derive(Debug)]
pub struct AttributeRecord {
    pub attribute_length: u32,
    // components_count: u16,
    pub components: Vec<AttributeRecordComponentInfo>,
}

impl AttributeName for AttributeRecord {
    const ATTRIBUTE_NAME: &'static str = "Record";
}

#[derive(Debug)]
pub struct AttributePermittedSubclasses {
    pub attribute_length: u32,
    // number_of_classes: u16,
    pub classes: Vec<u16>,
}

impl AttributeName for AttributePermittedSubclasses {
    const ATTRIBUTE_NAME: &'static str = "PermittedSubclasses";
}

#[derive(Debug, Clone)]
pub struct MalformedClassFile {
    file_path: String,
    msg: String
}

impl MalformedClassFile {
    // fn entry_wrong_length(path_str: &str, entry_name: &str, bytes_read: usize, bytes_expected: usize) -> MalformedClassFile {
    //     return MalformedClassFile { file_path: String::from(path_str), msg: format!("Napačna dolžina {}. Pričakovana: {}, dobljena: {}", entry_name, bytes_expected, bytes_read) };
    // }

    fn entry_wrong_value(path_str: &str, entry_name: &str, value_read: impl LowerHex, value_expected: impl LowerHex) -> MalformedClassFile {
        return MalformedClassFile { file_path: String::from(path_str), msg: format!("Napačna vrednost {}. Pričakovana: {:#0x}, dobljena: {:#0x}", entry_name, value_expected, value_read) }
    }

    fn entry_not_one_of(path_str: &str, entry_name: &str, value_read: impl LowerHex, values_allowed: Vec<impl LowerHex>) -> MalformedClassFile {
        let mut values_allowed_formatted = String::from("[");
        for value in &values_allowed[0..values_allowed.len()] {
            values_allowed_formatted.push_str(&format!("{:#0x}, ", value));
        }
        values_allowed_formatted.push_str(&format!("{:#0x}]", values_allowed[values_allowed.len() - 1]));

        return MalformedClassFile { file_path: String::from(path_str), msg: format!("Napačna vrednost {}. Pričakovana ena od: {}, dobljena: {:#0x}", entry_name, values_allowed_formatted, value_read) }
    }
}

impl fmt::Display for MalformedClassFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Napaka v class datoteki {}: {}.", self.file_path, self.msg)
    }
}

impl error::Error for MalformedClassFile {}

pub fn parse_class_file(file_path: &str) -> Result<ClassFile, Box<dyn error::Error>> {
    let file = File::open(file_path)?;
    // let mut reader: BufReader<File> = BufReader::with_capacity(READER_BUF_SIZE, file);
    let mut reader: BufReader<File> = BufReader::new(file);

    let magic = reader.read_u32::<BigEndian>()?;
    if magic != MAGIC {
        return Err(MalformedClassFile::entry_wrong_value(file_path, "MAGIC", magic, MAGIC).into());
    }

    let minor_version = reader.read_u16::<BigEndian>()?;
    let major_version = reader.read_u16::<BigEndian>()?;

    let constant_pool_count = reader.read_u16::<BigEndian>()?;
    let constant_pool = read_constant_pool(file_path, &mut reader, constant_pool_count)?;

    let access_flags = reader.read_u16::<BigEndian>()?;

    let this_class = reader.read_u16::<BigEndian>()?;
    let super_class = reader.read_u16::<BigEndian>()?;

    let interfaces_count = reader.read_u16::<BigEndian>()?;
    let interfaces = read_interfaces(&mut reader, interfaces_count)?;
    

    let fields_count = reader.read_u16::<BigEndian>()?;
    let fields = read_fields(file_path, &mut reader, fields_count, &constant_pool)?;

    let methods_count = reader.read_u16::<BigEndian>()?;
    let methods = read_methods(file_path, &mut reader, methods_count, &constant_pool)?;

    let attributes_count = reader.read_u16::<BigEndian>()?;
    let attributes = read_attributes(file_path, &mut reader, attributes_count, &constant_pool)?;

    return Ok(ClassFile {
        magic,
        minor_version,
        major_version,
        constant_pool_count,
        constant_pool,
        access_flags,
        this_class,
        super_class,
        interfaces,
        fields,
        methods,
        attributes,
    });
}

fn read_constant_pool(class_file_path: &str, reader: &mut BufReader<File>, constant_pool_count: u16) -> Result<Vec<CpInfo>, Box<dyn error::Error>> {
    // constant pool je 1-indexed in vsebuje constant_pool_count - 1 vnosov. Vec je zato za 1 večji in na indeksu 0 vsebuje "dummy" vnos.
    let mut constant_pool = Vec::with_capacity((constant_pool_count).into());
    constant_pool.push(CpInfo::Integer(CpInteger { bytes: [0; 4] }));

    for _ in 0..constant_pool_count - 1 {
        constant_pool.push(read_constant_pool_entry(class_file_path, reader)?);
    }

    return Ok(constant_pool);
}

fn read_constant_pool_entry(class_file_path: &str, reader: &mut BufReader<File>) -> Result<CpInfo, Box<dyn error::Error>> {
    let tag = reader.read_u8()?;

    match tag {
        CpUtf8::TAG => {
            let length = reader.read_u16::<BigEndian>()?;
            let mut bytes: Vec<u8> = Vec::with_capacity(length.into());
            for _ in 0..length {
                bytes.push(reader.read_u8()?);
            }
            let converted = modified_utf8_to_string(&bytes)?;
            return Ok(CpInfo::Utf8(CpUtf8 { bytes, converted }));
        },
        CpInteger::TAG => {
            let mut bytes = [0; 4];
            for i in 0..4 {
                bytes[i] = reader.read_u8()?;
            }
            return Ok(CpInfo::Integer(CpInteger { bytes }));
        },
        CpFloat::TAG => {
            let mut bytes = [0; 4];
            for i in 0..4 {
                bytes[i] = reader.read_u8()?;
            }
            return Ok(CpInfo::Float(CpFloat { bytes }));
        },
        CpLong::TAG => {
            let high_bytes = reader.read_u32::<BigEndian>()?;
            let low_bytes = reader.read_u32::<BigEndian>()?;
            return Ok(CpInfo::Long(CpLong { high_bytes, low_bytes }));
        },
        CpDouble::TAG => {
            let high_bytes = reader.read_u32::<BigEndian>()?;
            let low_bytes = reader.read_u32::<BigEndian>()?;
            return Ok(CpInfo::Double(CpDouble { high_bytes, low_bytes }));
        },
        CpClass::TAG => {
            let name_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::Class(CpClass { name_index }));
        },
        CpString::TAG => {
            let string_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::String(CpString { string_index }));
        },
        CpFieldRef::TAG => {
            let class_index = reader.read_u16::<BigEndian>()?;
            let name_and_type_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::FieldRef(CpFieldRef { class_index, name_and_type_index}));
        },
        CpMethodRef::TAG => {
            let class_index = reader.read_u16::<BigEndian>()?;
            let name_and_type_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::MethodRef(CpMethodRef { class_index , name_and_type_index }));
        },
        CpInterfaceMethodRef::TAG => {
            let class_index = reader.read_u16::<BigEndian>()?;
            let name_and_type_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::InterfaceMethodRef(CpInterfaceMethodRef { class_index, name_and_type_index }));
        },
        CpNameAndType::TAG => {
            let name_index = reader.read_u16::<BigEndian>()?;
            let descriptor_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::NameAndType(CpNameAndType { name_index , descriptor_index }));
        },
        CpMethodHandle::TAG => {
            let reference_kind = reader.read_u8()?;
            let reference_kind = match MethodHandleReferenceKind::try_from(reference_kind) {
                Ok(result) => result,
                Err(_) => return Err(MalformedClassFile::entry_not_one_of(class_file_path, "CONSTANT_POOL_METHOD_HANDLE_REFERENCE_KIND", reference_kind, MethodHandleReferenceKind::iter().map(|e| e as u8).collect()).into())
            };

            let reference_index = reader.read_u16::<BigEndian>()?;

            return Ok(CpInfo::MethodHandle(CpMethodHandle { reference_kind , reference_index }));
        },
        CpMethodType::TAG => {
            let descriptor_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::MethodType(CpMethodType { descriptor_index }));
        },
        CpDynamic::TAG => {
            let bootstrap_method_attr_index = reader.read_u16::<BigEndian>()?;
            let name_and_type_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::Dynamic(CpDynamic { bootstrap_method_attr_index, name_and_type_index}))
        },
        CpInvokeDynamic::TAG => {
            let bootstrap_method_attr_index = reader.read_u16::<BigEndian>()?;
            let name_and_type_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::InvokeDynamic(CpInvokeDynamic { bootstrap_method_attr_index, name_and_type_index}))
        },
        CpModule::TAG => {
            let name_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::Module(CpModule { name_index }))
        },
        CpPackage::TAG => {
            let name_index = reader.read_u16::<BigEndian>()?;
            return Ok(CpInfo::Package(CpPackage { name_index }));
        },
        _ => {
            return Err(MalformedClassFile::entry_not_one_of(class_file_path, "CONSTANT_POOL_TAG", tag, vec![CpUtf8::TAG, CpInteger::TAG, CpFloat::TAG, CpLong::TAG, CpDouble::TAG, CpClass::TAG, CpString::TAG, CpFieldRef::TAG, CpMethodRef::TAG, CpInterfaceMethodRef::TAG, CpNameAndType::TAG, CpMethodHandle::TAG, CpMethodType::TAG, CpDynamic::TAG, CpInvokeDynamic::TAG, CpModule::TAG, CpPackage::TAG]).into());
        }
    }
}

fn read_interfaces(reader: &mut BufReader<File>, interfaces_count: u16) -> Result<Vec<u16>, Box<dyn error::Error>> {
    let mut interfaces = Vec::with_capacity(interfaces_count.into());
    for _ in 0..interfaces_count {
        interfaces.push(reader.read_u16::<BigEndian>()?);
    }

    return Ok(interfaces);
}

fn read_fields(class_file_path: &str, reader: &mut BufReader<File>, fields_count: u16, constant_pool: &Vec<CpInfo>) -> Result<Vec<FieldInfo>, Box<dyn error::Error>> {
    let mut fields = Vec::with_capacity(fields_count.into());
    for _ in 0..fields_count {
        fields.push(read_field(class_file_path, reader, constant_pool)?);
    }

    return Ok(fields);
}

fn read_field(class_file_path: &str, reader: &mut BufReader<File>, constant_pool: &Vec<CpInfo>) -> Result<FieldInfo, Box<dyn error::Error>> {
    let access_flags = reader.read_u16::<BigEndian>()?;
    let name_index = reader.read_u16::<BigEndian>()?;
    let descriptor_index = reader.read_u16::<BigEndian>()?;
    let attributes_count = reader.read_u16::<BigEndian>()?;
    let attributes = read_attributes(class_file_path, reader, attributes_count, constant_pool)?;
    
    return Ok(FieldInfo { access_flags, name_index, descriptor_index, attributes });
}

fn read_attributes(class_file_path: &str, reader: &mut BufReader<File>, attributes_count: u16, constant_pool: &Vec<CpInfo>) -> Result<Vec<AttributeInfo>, Box<dyn error::Error>> {
    let mut attributes = Vec::with_capacity(attributes_count.into());
    for _ in 0..attributes_count {
        attributes.push(read_attribute(class_file_path, reader, constant_pool)?)
    }

    return Ok(attributes);
}

fn read_attribute(class_file_path: &str, reader: &mut BufReader<File>, constant_pool: &Vec<CpInfo>) -> Result<AttributeInfo, Box<dyn error::Error>> {
    let attribute_name_index = reader.read_u16::<BigEndian>()?;
    let attribute_length = reader.read_u32::<BigEndian>()?;

    let attribute_name_cp_utf8 = match &constant_pool[usize::from(attribute_name_index)] {
        CpInfo::Utf8(cp_utf8) => cp_utf8,
        _ => {
            return Err(MalformedClassFile { file_path: class_file_path.into(), msg: format!("attribute_name_index {} ne vodi to CpUtf8", attribute_name_index) }.into());
        }
    };

    match attribute_name_cp_utf8.converted.as_str() {
        AttributeConstantValue::ATTRIBUTE_NAME => {
            let constantvalue_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeInfo::ConstantValue(AttributeConstantValue { constantvalue_index }));
        },
        AttributeCode::ATTRIBUTE_NAME => {
            let max_stack = reader.read_u16::<BigEndian>()?;
            let max_locals = reader.read_u16::<BigEndian>()?;

            let code_length = reader.read_u32::<BigEndian>()?;
            let mut code = Vec::new();
            for _ in 0..code_length {
                code.push(reader.read_u8()?);
            }

            let exception_table_length = reader.read_u16::<BigEndian>()?;
            let mut exception_table = Vec::with_capacity(exception_table_length.into());
            for _ in 0..exception_table_length {
                exception_table.push(ExceptionTableEntry {
                    start_pc: reader.read_u16::<BigEndian>()?,
                    end_pc: reader.read_u16::<BigEndian>()?,
                    handler_pc: reader.read_u16::<BigEndian>()?,
                    catch_type: reader.read_u16::<BigEndian>()?,
                });
            }

            let attributes_count = reader.read_u16::<BigEndian>()?;
            let attributes = read_attributes(class_file_path, reader, attributes_count, constant_pool)?;

            return Ok(AttributeInfo::Code(AttributeCode { attribute_length, max_stack, max_locals, code, exception_table, attributes}))
        },
        AttributeStackMapTable::ATTRIBUTE_NAME => {
            let number_of_entries = reader.read_u16::<BigEndian>()?;
            let mut entries = Vec::with_capacity(number_of_entries.into());
            for _ in 0..number_of_entries {
                entries.push(read_stack_map_frame(class_file_path, reader)?);
            }

            return Ok(AttributeInfo::StackMapTable(AttributeStackMapTable { attribute_length, entries }));
        },
        AttributeExceptions::ATTRIBUTE_NAME => {
            let number_of_exceptions = reader.read_u16::<BigEndian>()?;
            let mut exception_index_table = Vec::with_capacity(number_of_exceptions.into());
            for _ in 0..number_of_exceptions {
                exception_index_table.push(reader.read_u16::<BigEndian>()?);
            }

            return Ok(AttributeInfo::Exceptions(AttributeExceptions { attribute_length, exception_index_table }));
        },
        AttributeInnerClasses::ATTRIBUTE_NAME => {
            let number_of_classes = reader.read_u16::<BigEndian>()?;
            let mut classes = Vec::with_capacity(number_of_classes.into());
            for _ in 0..number_of_classes {
                classes.push(AttributeInnerClassesClass {
                    inner_class_info_index: reader.read_u16::<BigEndian>()?,
                    outer_class_info_index: reader.read_u16::<BigEndian>()?,
                    inner_name_index: reader.read_u16::<BigEndian>()?,
                    inner_class_access_flags: reader.read_u16::<BigEndian>()?,
                });
            }

            return Ok(AttributeInfo::InnerClasses(AttributeInnerClasses { attribute_length, classes }));
        },
        AttributeEnclosingMethod::ATTRIBUTE_NAME => {
            let class_index = reader.read_u16::<BigEndian>()?;
            let method_index = reader.read_u16::<BigEndian>()?;

            return Ok(AttributeInfo::EnclosingMethod(AttributeEnclosingMethod { class_index, method_index }));
        },
        AttributeSynthetic::ATTRIBUTE_NAME => {
            return Ok(AttributeInfo::Synthetic(AttributeSynthetic {}));
        },
        AttributeSignature::ATTRIBUTE_NAME => {
            let signature_index = reader.read_u16::<BigEndian>()?;

            return Ok(AttributeInfo::Signature(AttributeSignature { signature_index }));
        },
        AttributeSourceFile::ATTRIBUTE_NAME => {
            let sourcefile_index = reader.read_u16::<BigEndian>()?;

            return Ok(AttributeInfo::SourceFile(AttributeSourceFile { sourcefile_index }));
        },
        AttributeSourceDebugExtension::ATTRIBUTE_NAME => {
            let mut debug_extension = Vec::with_capacity(attribute_length.try_into()?);
            for _ in 0..attribute_length {
                debug_extension.push(reader.read_u8()?);
            }

            return Ok(AttributeInfo::SourceDebugExtension(AttributeSourceDebugExtension { debug_extension }));
        },
        AttributeLineNumberTable::ATTRIBUTE_NAME => {
            let line_number_table_length = reader.read_u16::<BigEndian>()?;
            let mut line_number_table = Vec::with_capacity(line_number_table_length.into());
            for _ in 0..line_number_table_length {
                line_number_table.push(AttributeLineNumberTableEntry {
                    start_pc: reader.read_u16::<BigEndian>()?,
                    line_number: reader.read_u16::<BigEndian>()?,
                });
            }

            return Ok(AttributeInfo::LineNumberTable(AttributeLineNumberTable { attribute_length, line_number_table }));
        },
        AttributeLocalVariableTable::ATTRIBUTE_NAME => {
            let local_variable_table_length = reader.read_u16::<BigEndian>()?;
            let mut local_variable_table = Vec::with_capacity(local_variable_table_length.into());
            for _ in 0..local_variable_table_length {
                local_variable_table.push(AttributeLocalVariableTableEntry {
                    start_pc: reader.read_u16::<BigEndian>()?,
                    length: reader.read_u16::<BigEndian>()?,
                    name_index: reader.read_u16::<BigEndian>()?,
                    descriptor_index: reader.read_u16::<BigEndian>()?,
                    index: reader.read_u16::<BigEndian>()?,
                });
            }

            return Ok(AttributeInfo::LocalVariableTable(AttributeLocalVariableTable { attribute_length, local_variable_table }));
        },
        AttributeLocalVariableTypeTable::ATTRIBUTE_NAME => {
            let local_variable_table_length = reader.read_u16::<BigEndian>()?;
            let mut local_variable_table = Vec::with_capacity(local_variable_table_length.into());
            for _ in 0..local_variable_table_length {
                local_variable_table.push(AttributeLocalVariableTypeTableEntry {
                    start_pc: reader.read_u16::<BigEndian>()?,
                    length: reader.read_u16::<BigEndian>()?,
                    name_index: reader.read_u16::<BigEndian>()?,
                    signature_index: reader.read_u16::<BigEndian>()?,
                    index: reader.read_u16::<BigEndian>()?,
                })
            }

            return Ok(AttributeInfo::LocalVariableTypeTable(AttributeLocalVariableTypeTable { attribute_length, local_variable_table }));
        },
        AttributeDeprecated::ATTRIBUTE_NAME => {
            return Ok(AttributeInfo::Deprecated(AttributeDeprecated {}));
        },
        AttributeRuntimeVisibleAnnotations::ATTRIBUTE_NAME => {
            let num_annotations = reader.read_u16::<BigEndian>()?;
            let mut annotations = Vec::with_capacity(num_annotations.into());
            for _ in 0..num_annotations {
                annotations.push(read_runtime_annotations_entry(class_file_path, reader)?);
            }

            return Ok(AttributeInfo::RuntimeVisibleAnnotations(AttributeRuntimeVisibleAnnotations { attribute_length, annotations }));
        },
        AttributeRuntimeInvisibleAnnotations::ATTRIBUTE_NAME => {
            let num_annotations = reader.read_u16::<BigEndian>()?;
            let mut annotations = Vec::with_capacity(num_annotations.into());
            for _ in 0..num_annotations {
                annotations.push(read_runtime_annotations_entry(class_file_path, reader)?);
            }

            return Ok(AttributeInfo::RuntimeInvisibleAnnotations(AttributeRuntimeInvisibleAnnotations { attribute_length, annotations }));
        },
        AttributeRuntimeVisibleParameterAnnotations::ATTRIBUTE_NAME => {
            let num_parameters = reader.read_u8()?;
            let mut parameter_annotations = Vec::with_capacity(num_parameters.into());
            for _ in 0..num_parameters {
                let num_annotations = reader.read_u16::<BigEndian>()?;
                let mut annotations = Vec::with_capacity(num_annotations.into());
                for _ in 0..num_annotations {
                    annotations.push(read_runtime_annotations_entry(class_file_path, reader)?)
                }

                parameter_annotations.push(annotations);
            }

            return Ok(AttributeInfo::RuntimeVisibleParameterAnnotations(AttributeRuntimeVisibleParameterAnnotations { attribute_length, parameter_annotations }));
        },
        AttributeRuntimeInvisibleParameterAnnotations::ATTRIBUTE_NAME => {
            let num_parameters = reader.read_u8()?;
            let mut parameter_annotations = Vec::with_capacity(num_parameters.into());
            for _ in 0..num_parameters {
                let num_annotations = reader.read_u16::<BigEndian>()?;
                let mut annotations = Vec::with_capacity(num_annotations.into());
                for _ in 0..num_annotations {
                    annotations.push(read_runtime_annotations_entry(class_file_path, reader)?)
                }

                parameter_annotations.push(annotations);
            }

            return Ok(AttributeInfo::RuntimeInvisibleParameterAnnotations(AttributeRuntimeInvisibleParameterAnnotations { attribute_length, parameter_annotations }));
        },
        AttributeRuntimeVisibleTypeAnnotations::ATTRIBUTE_NAME => {
            let num_annotations = reader.read_u16::<BigEndian>()?;
            let mut annotations = Vec::with_capacity(num_annotations.into());
            for _ in 0..num_annotations {
                annotations.push(read_runtime_type_annotations_entry(class_file_path, reader)?);
            }

            return Ok(AttributeInfo::RuntimeVisibleTypeAnnotations(AttributeRuntimeVisibleTypeAnnotations { attribute_length, annotations }));
        },
        AttributeRuntimeInvisibleTypeAnnotations::ATTRIBUTE_NAME => {
            let num_annotations = reader.read_u16::<BigEndian>()?;
            let mut annotations = Vec::with_capacity(num_annotations.into());
            for _ in 0..num_annotations {
                annotations.push(read_runtime_type_annotations_entry(class_file_path, reader)?);
            }

            return Ok(AttributeInfo::RuntimeInvisibleTypeAnnotations(AttributeRuntimeInvisibleTypeAnnotations { attribute_length, annotations }));
        },
        AttributeAnnotationDefault::ATTRIBUTE_NAME => {
            let default_value = read_annotations_element_value(class_file_path, reader)?;
            return Ok(AttributeInfo::AnnotationDefault(AttributeAnnotationDefault { attribute_length, default_value }));
        },
        AttributeBootstrapMethods::ATTRIBUTE_NAME => {
            let num_bootstrap_methods = reader.read_u16::<BigEndian>()?;
            let mut bootstrap_methods = Vec::with_capacity(num_bootstrap_methods.into());
            for _ in 0..num_bootstrap_methods {
                let bootstrap_method_ref = reader.read_u16::<BigEndian>()?;
                let num_bootstrap_arguments = reader.read_u16::<BigEndian>()?;
                let mut bootstrap_arguments = Vec::with_capacity(num_bootstrap_arguments.into());
                for _ in 0..num_bootstrap_arguments {
                    bootstrap_arguments.push(reader.read_u16::<BigEndian>()?);
                }

                bootstrap_methods.push(AttributeBootstrapMethodsEntry {
                    bootstrap_method_ref,
                    bootstrap_arguments,
                });
            }

            return Ok(AttributeInfo::BootstrapMethods(AttributeBootstrapMethods { attribute_length, bootstrap_methods }));
        },
        AttributeMethodParameters::ATTRIBUTE_NAME => {
            let parameters_count = reader.read_u8()?;
            let mut parameters = Vec::with_capacity(parameters_count.into());
            for _ in 0..parameters_count {
                parameters.push(AttributeMethodParametersEntry {
                    name_index: reader.read_u16::<BigEndian>()?,
                    access_flags: reader.read_u16::<BigEndian>()?,
                });
            }

            return Ok(AttributeInfo::MethodParameters(AttributeMethodParameters { attribute_length, parameters }));
        },
        AttributeModule::ATTRIBUTE_NAME => {
            let module_name_index = reader.read_u16::<BigEndian>()?;
            let module_flags = reader.read_u16::<BigEndian>()?;
            let module_version_index = reader.read_u16::<BigEndian>()?;

            let requires_count = reader.read_u16::<BigEndian>()?;
            let mut requires = Vec::with_capacity(requires_count.into());
            for _ in 0..requires_count {
                requires.push(AttributeModuleRequiresEntry {
                    requires_index: reader.read_u16::<BigEndian>()?,
                    requires_flags: reader.read_u16::<BigEndian>()?,
                    requires_version_index: reader.read_u16::<BigEndian>()?,
                })
            }

            let exports_count = reader.read_u16::<BigEndian>()?;
            let mut exports = Vec::with_capacity(exports_count.into());
            for _ in 0..exports_count {
                let exports_index = reader.read_u16::<BigEndian>()?;
                let exports_flags = reader.read_u16::<BigEndian>()?;

                let exports_to_count = reader.read_u16::<BigEndian>()?;
                let mut exports_to_index = Vec::with_capacity(exports_to_count.into());
                for _ in 0..exports_to_count {
                    exports_to_index.push(reader.read_u16::<BigEndian>()?);
                }

                exports.push(AttributeModuleExportsEntry {
                    exports_index,
                    exports_flags,
                    exports_to_index,
                })
            }

            let opens_count = reader.read_u16::<BigEndian>()?;
            let mut opens = Vec::with_capacity(opens_count.into());
            for _ in 0..opens_count {
                let opens_index = reader.read_u16::<BigEndian>()?;
                let opens_flags = reader.read_u16::<BigEndian>()?;

                let opens_to_count = reader.read_u16::<BigEndian>()?;
                let mut opens_to_index = Vec::with_capacity(opens_to_count.into());
                for _ in 0..opens_to_count {
                    opens_to_index.push(reader.read_u16::<BigEndian>()?);
                }

                opens.push(AttributeModuleOpensEntry {
                    opens_index,
                    opens_flags,
                    opens_to_index,
                })
            }

            let uses_count = reader.read_u16::<BigEndian>()?;
            let mut uses_index = Vec::with_capacity(uses_count.into());
            for _ in 0..uses_count {
                uses_index.push(reader.read_u16::<BigEndian>()?);
            }

            let provides_count = reader.read_u16::<BigEndian>()?;
            let mut provides = Vec::with_capacity(provides_count.into());
            for _ in 0..provides_count {
                let provides_index = reader.read_u16::<BigEndian>()?;

                let provides_with_count = reader.read_u16::<BigEndian>()?;
                let mut provides_with_index = Vec::with_capacity(provides_with_count.into());
                for _ in 0..provides_with_count {
                    provides_with_index.push(reader.read_u16::<BigEndian>()?);
                }

                provides.push(AttributeModuleProvidesEntry {
                    provides_index,
                    provides_with_index,
                });
            }

            return Ok(AttributeInfo::Module(AttributeModule {
                attribute_length,
                module_name_index,
                module_flags,
                module_version_index,
                requires,
                exports,
                opens,
                uses_index,
                provides,
            }));
        },
        AttributeModulePackages::ATTRIBUTE_NAME => {
            let package_count = reader.read_u16::<BigEndian>()?;
            let mut package_index = Vec::with_capacity(package_count.into());
            for _ in 0..package_count {
                package_index.push(reader.read_u16::<BigEndian>()?);
            }

            return Ok(AttributeInfo::ModulePackages(AttributeModulePackages { attribute_length, package_index }));
        },
        AttributeModuleMainClass::ATTRIBUTE_NAME => {
            let main_class_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeInfo::ModuleMainClass(AttributeModuleMainClass { main_class_index }));
        },
        AttributeNestHost::ATTRIBUTE_NAME => {
            let host_class_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeInfo::NestHost(AttributeNestHost { host_class_index }));
        },
        AttributeNestMembers::ATTRIBUTE_NAME => {
            let number_of_classes = reader.read_u16::<BigEndian>()?;
            let mut classes = Vec::with_capacity(number_of_classes.into());
            for _ in 0..number_of_classes {
                classes.push(reader.read_u16::<BigEndian>()?);
            }

            return Ok(AttributeInfo::NestMembers(AttributeNestMembers { attribute_length, classes }));
        },
        AttributeRecord::ATTRIBUTE_NAME => {
            let components_count = reader.read_u16::<BigEndian>()?;
            let mut components = Vec::with_capacity(components_count.into());
            for _ in 0..components_count {
                let name_index = reader.read_u16::<BigEndian>()?;
                let descriptor_index = reader.read_u16::<BigEndian>()?;

                let attributes_count = reader.read_u16::<BigEndian>()?;
                let attributes = read_attributes(class_file_path, reader, attributes_count, constant_pool)?;

                components.push(AttributeRecordComponentInfo {
                    name_index,
                    descriptor_index,
                    attributes,
                });
            }

            return Ok(AttributeInfo::Record(AttributeRecord { attribute_length, components }));
        },
        AttributePermittedSubclasses::ATTRIBUTE_NAME => {
            let number_of_classes = reader.read_u16::<BigEndian>()?;
            let mut classes = Vec::with_capacity(number_of_classes.into());
            for _ in 0..number_of_classes {
                classes.push(reader.read_u16::<BigEndian>()?);
            }

            return Ok(AttributeInfo::PermittedSubclasses(AttributePermittedSubclasses { attribute_length, classes}));
        }
        _ => {
            return Err(MalformedClassFile { file_path: class_file_path.into(), msg: format!("neznano ime attributa: {}", attribute_name_cp_utf8.converted) }.into());
        }
    }
}

fn read_stack_map_frame(class_file_path: &str, reader: &mut BufReader<File>, ) -> Result<StackMapFrame, Box<dyn error::Error>> {
    let frame_type = reader.read_u8()?;
    match frame_type {
        StackMapSameFrame::TAG_LOWER..=StackMapSameFrame::TAG_UPPER => {
            return Ok(StackMapFrame::SameFrame(StackMapSameFrame { frame_type }));
        },
        StackMapSameLocals1StackItemFrame::TAG_LOWER..=StackMapSameLocals1StackItemFrame::TAG_UPPER => {
            let stack_entry = read_verification_type_info(class_file_path, reader)?;
            return Ok(StackMapFrame::SameLocals1StackItemFrame(StackMapSameLocals1StackItemFrame { frame_type, stack_entry }));
        },
        StackMapSameLocals1StackItemFrameExtended::TAG => {
            let offset_delta = reader.read_u16::<BigEndian>()?;
            let stack_entry = read_verification_type_info(class_file_path, reader)?;
            return Ok(StackMapFrame::SameLocals1StackItemFrameExtended(StackMapSameLocals1StackItemFrameExtended { frame_type, offset_delta, stack_entry }));
        },
        StackMapChopFrame::TAG_LOWER..=StackMapChopFrame::TAG_UPPER => {
            let offset_delta = reader.read_u16::<BigEndian>()?;
            return Ok(StackMapFrame::ChopFrame(StackMapChopFrame { frame_type, offset_delta }));
        },
        StackMapSameFrameExtended::TAG => {
            let offset_delta = reader.read_u16::<BigEndian>()?;
            return Ok(StackMapFrame::SameFrameExtended(StackMapSameFrameExtended { frame_type, offset_delta }));
        },
        StackMapAppendFrame::TAG_LOWER..=StackMapAppendFrame::TAG_UPPER => {
            let offset_delta = reader.read_u16::<BigEndian>()?;

            let number_of_locals: usize = (frame_type - 251).into();
            let mut locals = Vec::with_capacity(number_of_locals);
            for _ in 0..number_of_locals {
                locals.push(read_verification_type_info(class_file_path, reader)?);
            }

            return Ok(StackMapFrame::AppendFrame(StackMapAppendFrame { frame_type, offset_delta, locals }));
        },
        StackMapFullFrame::TAG => {
            let offset_delta = reader.read_u16::<BigEndian>()?;

            let number_of_locals = reader.read_u16::<BigEndian>()?;
            let mut locals = Vec::with_capacity(number_of_locals.into());
            for _ in 0..number_of_locals {
                locals.push(read_verification_type_info(class_file_path, reader)?);
            }

            let number_of_stack_items = reader.read_u16::<BigEndian>()?;
            let mut stack = Vec::with_capacity(number_of_stack_items.into());
            for _ in 0..number_of_stack_items {
                stack.push(read_verification_type_info(class_file_path, reader)?);
            }

            return Ok(StackMapFrame::FullFrame(StackMapFullFrame { frame_type, offset_delta, locals, stack }));
        },
        _ => {
            return Err(MalformedClassFile { file_path: class_file_path.into(), msg: format!("Neznan StackMapFrame frame_type: {:#0x}", frame_type) }.into());
        }
    }
}

fn read_verification_type_info(class_file_path: &str, reader: &mut BufReader<File>) -> Result<VerificationTypeInfo, Box<dyn error::Error>> {
    let tag = reader.read_u8()?;
    match tag {
        VerificationTypeTopVariableInfo::TAG => {
            return Ok(VerificationTypeInfo::TopVariable(VerificationTypeTopVariableInfo {}));
        },
        VerificationTypeIntegerVariableInfo::TAG => {
            return Ok(VerificationTypeInfo::IntegerVariable(VerificationTypeIntegerVariableInfo {}));
        },
        VerificationTypeFloatVariableInfo::TAG => {
            return Ok(VerificationTypeInfo::FloatVariable(VerificationTypeFloatVariableInfo {}));
        },
        VerificationTypeNullVariableInfo::TAG => {
            return Ok(VerificationTypeInfo::NullVariable(VerificationTypeNullVariableInfo {}));
        },
        VerificationTypeUninitializedThisVariableInfo::TAG => {
            return Ok(VerificationTypeInfo::UninitializedThisVariable(VerificationTypeUninitializedThisVariableInfo {}));
        },
        VerificationTypeObjectVariableInfo::TAG => {
            let cpool_index = reader.read_u16::<BigEndian>()?;
            return Ok(VerificationTypeInfo::ObjectVariable(VerificationTypeObjectVariableInfo { cpool_index }));
        },
        VerificationTypeUninitializedVariableInfo::TAG => {
            let offset = reader.read_u16::<BigEndian>()?;
            return Ok(VerificationTypeInfo::UninitializedVariable(VerificationTypeUninitializedVariableInfo { offset }));
        },
        VerificationTypeLongVariableInfo::TAG => {
            return Ok(VerificationTypeInfo::LongVariable(VerificationTypeLongVariableInfo {}));
        },
        VerificationTypeDoubleVariableInfo::TAG => {
            return Ok(VerificationTypeInfo::DoubleVariable(VerificationTypeDoubleVariableInfo {}));
        }
        _ => {
            return Err(MalformedClassFile { file_path: class_file_path.into(), msg: format!("Neznan VerificationTypeInfo tag: {:#0x}", tag) }.into());
        }
    }
}

fn read_runtime_annotations_entry(class_file_path: &str, reader: &mut BufReader<File>) -> Result<AttributeRuntimeAnnotationsEntry, Box<dyn error::Error>> {
    let type_index = reader.read_u16::<BigEndian>()?;
    let num_element_value_pairs = reader.read_u16::<BigEndian>()?;
    let mut element_value_pairs = Vec::with_capacity(num_element_value_pairs.into());
    for _ in 0..num_element_value_pairs {
        element_value_pairs.push(read_annotations_element_value_pair(class_file_path, reader)?);
    }

    return Ok(AttributeRuntimeAnnotationsEntry { type_index, element_value_pairs })
}

fn read_annotations_element_value_pair(class_file_path: &str, reader: &mut BufReader<File>) -> Result<AttributeAnnotationsElementValuePair, Box<dyn error::Error>> {
    let element_name_index = reader.read_u16::<BigEndian>()?;
    let element_value = read_annotations_element_value(class_file_path, reader)?;

    return Ok(AttributeAnnotationsElementValuePair { element_name_index, element_value })
}

fn read_annotations_element_value(class_file_path: &str, reader: &mut BufReader<File>) -> Result<AttributeAnnotationsElementValue, Box<dyn error::Error>> {
    let tag = reader.read_u8()?;
    match tag {
        AttributeAnnotationsElementValueByte::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Byte(AttributeAnnotationsElementValueByte { const_value_index }));
        },
        AttributeAnnotationsElementValueChar::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Char(AttributeAnnotationsElementValueChar { const_value_index }));
        },
        AttributeAnnotationsElementValueDouble::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Double(AttributeAnnotationsElementValueDouble { const_value_index }));
        },
        AttributeAnnotationsElementValueFloat::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Float(AttributeAnnotationsElementValueFloat { const_value_index }));
        },
        AttributeAnnotationsElementValueInt::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Int(AttributeAnnotationsElementValueInt { const_value_index }));
        },
        AttributeAnnotationsElementValueLong::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Long(AttributeAnnotationsElementValueLong { const_value_index }));
        },
        AttributeAnnotationsElementValueShort::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Short(AttributeAnnotationsElementValueShort { const_value_index }));
        },
        AttributeAnnotationsElementValueBoolean::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Boolean(AttributeAnnotationsElementValueBoolean { const_value_index }));
        },
        AttributeAnnotationsElementValueString::TAG => {
            let const_value_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::String(AttributeAnnotationsElementValueString { const_value_index }));
        },
        AttributeAnnotationsElementValueEnumClass::TAG => {
            let type_name_index = reader.read_u16::<BigEndian>()?;
            let const_name_index = reader.read_u16::<BigEndian>()?;

            return Ok(AttributeAnnotationsElementValue::EnumClass(AttributeAnnotationsElementValueEnumClass { type_name_index, const_name_index }));
        },
        AttributeAnnotationsElementValueClass::TAG => {
            let class_info_index = reader.read_u16::<BigEndian>()?;
            return Ok(AttributeAnnotationsElementValue::Class(AttributeAnnotationsElementValueClass { class_info_index }));
        },
        AttributeAnnotationsElementValueAnnotationInterface::TAG => {
            let annotation_value = read_runtime_annotations_entry(class_file_path, reader)?;
            return Ok(AttributeAnnotationsElementValue::AnnotationInterface(AttributeAnnotationsElementValueAnnotationInterface { annotation_value }));
        },
        AttributeAnnotationsElementValueArrayType::TAG => {
            let num_values = reader.read_u16::<BigEndian>()?;
            let mut values = Vec::with_capacity(num_values.into());
            for _ in 0..num_values {
                values.push(read_annotations_element_value(class_file_path, reader)?);
            }

            return Ok(AttributeAnnotationsElementValue::ArrayType(AttributeAnnotationsElementValueArrayType { values }));
        },
        _ => {
            return Err(MalformedClassFile { file_path: class_file_path.into(), msg: format!("Neznan AttributeAnnotationsElementValue tag: {:#0x}", tag) }.into());
        }
    }
}

fn read_runtime_type_annotations_entry(class_file_path: &str, reader: &mut BufReader<File>) -> Result<AttributeRuntimeTypeAnnotationsEntry, Box<dyn error::Error>> {
    let target_type = reader.read_u8()?;
    let target_info;
    match target_type {
        0x00 | 0x01 => {
            let type_parameter_index = reader.read_u8()?;
            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::TypeParameterTarget(AttributeRuntimeTypeAnnotationsEntryTypeParameterTarget { type_parameter_index });
        },
        0x10 => {
            let supertype_index = reader.read_u16::<BigEndian>()?;

            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::SuperTypeTarget(AttributeRuntimeTypeAnnotationsEntrySuperTypeTarget { supertype_index });
        }
        0x11 | 0x12 => {
            let type_parameter_index = reader.read_u8()?;
            let bound_index = reader.read_u8()?;

            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::TypeParameterBoundTarget(AttributeRuntimeTypeAnnotationsEntryTypeParameterBoundTarget { type_parameter_index, bound_index });
        },
        0x13 | 0x14 | 0x15 => {
            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::EmptyTarget(AttributeRuntimeTypeAnnotationsEntryEmptyTarget {});
        },
        0x16 => {
            let formal_parameter_index = reader.read_u8()?;
            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::FormalParameterTarget(AttributeRuntimeTypeAnnotationsEntryFormalParameterTarget { formal_parameter_index });
        },
        0x17 => {
            let throws_type_index = reader.read_u16::<BigEndian>()?;
            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::ThrowsTarget(AttributeRuntimeTypeAnnotationsEntryThrowsTarget { throws_type_index });
        },
        0x40 | 0x41 => {
            let table_length = reader.read_u16::<BigEndian>()?;
            let mut table = Vec::with_capacity(table_length.into());
            for _ in 0..table_length {
                table.push(AttributeRuntimeTypeAnnotationsEntryLocalvarTargetTableEntry {
                    start_pc: reader.read_u16::<BigEndian>()?,
                    length: reader.read_u16::<BigEndian>()?,
                    index: reader.read_u16::<BigEndian>()?,
                });
            }
            
            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::LocalvarTarget(AttributeRuntimeTypeAnnotationsEntryLocalvarTarget { table });
        },
        0x42 => {
            let exception_table_index = reader.read_u16::<BigEndian>()?;
            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::CatchTarget(AttributeRuntimeTypeAnnotationsEntryCatchTarget { exception_table_index });
        },
        0x43 | 0x44 | 0x45 | 0x46 => {
            let offset = reader.read_u16::<BigEndian>()?;
            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::OffsetTarget(AttributeRuntimeTypeAnnotationsEntryOffsetTarget { offset });
        },
        0x47 | 0x48 | 0x49 | 0x4A | 0x4B => {
            let offset = reader.read_u16::<BigEndian>()?;
            let type_argument_index = reader.read_u8()?;

            target_info = AttributeRuntimeTypeAnnotationsEntryTargetInfo::TypeArgumentTarget(AttributeRuntimeTypeAnnotationsEntryTypeArgumentTarget { offset, type_argument_index });
        },
        _ => {
            return Err(MalformedClassFile { file_path: class_file_path.into(), msg: format!("Neznan AttributeRuntimeTypeAnnotationsEntryTargetInfo target_type: {:#0x}", target_type) }.into());
        }
    };

    let path_length = reader.read_u8()?;
    let mut target_path = Vec::with_capacity(path_length.into());
    for _ in 0..path_length {
        target_path.push(AttributeRuntimeVisibleTypeAnnotationsEntryTargetPathEntry {
            type_path_kind: reader.read_u8()?,
            type_argument_index: reader.read_u8()?,
        });
    }

    let type_index = reader.read_u16::<BigEndian>()?;

    let num_element_value_pairs = reader.read_u16::<BigEndian>()?;
    let mut element_value_pairs = Vec::with_capacity(num_element_value_pairs.into());
    for _ in 0..num_element_value_pairs {
        element_value_pairs.push(read_annotations_element_value_pair(class_file_path, reader)?);
    }

    return Ok(AttributeRuntimeTypeAnnotationsEntry {
        target_type,
        target_info,
        target_path,
        type_index,
        element_value_pairs,
    });
}

fn read_methods(class_file_path: &str, reader: &mut BufReader<File>, methods_count: u16, constant_pool: &Vec<CpInfo>) -> Result<Vec<MethodInfo>, Box<dyn error::Error>> {
    let mut methods = Vec::with_capacity(methods_count.into());
    for _ in 0..methods_count {
        methods.push(read_method(class_file_path, reader, constant_pool)?);
    }

    return Ok(methods);
}

fn read_method(class_file_path: &str, reader: &mut BufReader<File>, constant_pool: &Vec<CpInfo>) -> Result<MethodInfo, Box<dyn error::Error>> {
    let access_flags = reader.read_u16::<BigEndian>()?;
    let name_index = reader.read_u16::<BigEndian>()?;
    let descriptor_index = reader.read_u16::<BigEndian>()?;

    let attributes_count = reader.read_u16::<BigEndian>()?;
    let attributes = read_attributes(class_file_path, reader, attributes_count, constant_pool)?;

    return Ok(MethodInfo {
        access_flags,
        name_index,
        descriptor_index,
        attributes,
    })
}

// struct CpInfo {
//     tag: u8,
//     info: Vec<u8>
// }

// enum CpInfo {
//     Utf8 {
//         length: u16,
//         /** Shranjeni v modified UTF-8! (glej https://docs.oracle.com/javase/specs/jvms/se22/html/jvms-4.html#jvms-4.4.7) */
//         bytes: Vec<u8>
//     },
//     Integer {
//         bytes: [u8; 4]
//     },
//     Float {
//         bytes: [u8; 4]
//     },
//     Long {
//         high_bytes: u32,
//         low_bytes: u32
//     },
//     Double {
//         high_bytes: u32,
//         low_bytes: u32
//     },
//     Class {
//         name_index: u16
//     },
//     String {
//         string_index: u16
//     },
//     FieldRef {
//         class_index: u16,
//         name_and_type_index: u16
//     },
//     MethodRef {
//         class_index: u16,
//         name_and_type_index: u16
//     },
//     InterfaceMethodRef {
//         class_index: u16,
//         name_and_type_index: u16
//     },
//     NameAndType {
//         name_index: u16,
//         descriptor_index: u16
//     },
//     MethodHandle {
//         reference_kind: MethodHandleReferenceKind,
//         reference_index: u16
//     },
//     MethodInfo {
//         descriptor_index: u16
//     },
//     Dynamic {
//         bootstrap_method_attr_index: u16,
//         name_and_type_index: u16
//     },
//     InvokeDynamic {
//         bootstrap_method_attr_index: u16,
//         name_and_type_index: u16
//     },
//     Module {
//         name_index: u16
//     },
//     Package {
//         name_index: u16
//     }
// }

// impl CpInfo {
//     pub fn tag(self) -> u8 {
//         match self {
//             CpInfo::Utf8 { length, bytes } => 1,
//             CpInfo::Integer { bytes } => 3,
//             CpInfo::Float { bytes } => 4,
//             CpInfo::Long { high_bytes, low_bytes } => 5,
//             CpInfo::Double { high_bytes, low_bytes } => 6,
//             CpInfo::Class { name_index } => 7,
//             CpInfo::String { string_index } => 8,
//             CpInfo::FieldRef { class_index, name_and_type_index } => 9,
//             CpInfo::MethodRef { class_index, name_and_type_index } => 10,
//             CpInfo::InterfaceMethodRef { class_index, name_and_type_index } => 11,
//             CpInfo::NameAndType { name_index, descriptor_index } => 12,
//             CpInfo::MethodHandle { reference_kind, reference_index } => 15,
//             CpInfo::MethodInfo { descriptor_index } => 16,
//             CpInfo::Dynamic { bootstrap_method_attr_index, name_and_type_index } => 17,
//             CpInfo::InvokeDynamic { bootstrap_method_attr_index, name_and_type_index } => 18,
//             CpInfo::Module { name_index } => 19,
//             CpInfo::Package { name_index } => 20
//         }
//     }
// }

// const CP_TAG_UTF8: u8 = 1;
// const CP_TAG_INTEGER: u8 = 3;
// const CP_TAG_FLOAT: u8 = 4;
// const CP_TAG_LONG: u8 = 5;
// const CP_TAG_DOUBLE: u8 = 6;
// const CP_TAG_CLASS: u8 = 7;
// const CP_TAG_STRING: u8 = 8;
// const CP_TAG_FIELDREF: u8 = 9;
// const CP_TAG_METHODREF: u8 = 10;
// const CP_TAG_INTERFACE_METHODREF: u8 = 11;
// const CP_TAG_NAME_AND_TYPE: u8 = 12;
// const CP_TAG_METHOD_HANDLE: u8 = 15;
// const CP_TAG_METHOD_TYPE: u8 = 16;
// const CP_TAG_DYNAMIC: u8 = 17;
// const CP_TAG_INVOKE_DYNAMIC: u8 = 18;
// const CP_TAG_MODULE: u8 = 19;
// const CP_TAG_PACKAGE: u8 = 20;