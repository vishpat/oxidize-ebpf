extern crate rbpf;
use rbpf::helpers;
use rbpf::assembler::assemble;

#[test]
fn test_vm_add() {
    let prog = assemble("
        mov32 r0, 1 
        jeq r0, 0, +1
        jeq r0, 1, 2
        mov32 r0, 1
        ja +1
        mov32 r0, 2
        exit").unwrap();
    let vm = rbpf::EbpfVmNoData::new(Some(&prog)).unwrap();
    assert_eq!(vm.execute_program().unwrap(), 0x2);
}