import { describe, expect, it } from "vitest";
import { ExecutionList, IndexChange, LevelChange } from "../execution-model";

describe("ExecutionList", () => {
  const list2 = new ExecutionList([
    { id: "1", index: 0, level: 0 },
    { id: "2", index: 1, level: 0 },
    { id: "3", index: 0, level: 1 },
    { id: "4", index: 1, level: 1 },
    { id: "5", index: 0, level: 2 },
    { id: "6", index: 1, level: 2 },
    { id: "7", index: 2, level: 0 },
  ]);

  it("Move 1 down to the end", () => {
    const diff = list2.getChange({ id: "1" }, [
      "2",
      "3",
      "4",
      "5",
      "1",
      "6",
      "7",
    ]);

    expect(diff).toBeInstanceOf(LevelChange);
    expect((diff as LevelChange).parent?.id).toBe("4");
  });

  it("Index change", () => {
    const diff = list2.getChange({ id: "5" }, [
      "1",
      "2",
      "3",
      "4",
      "6",
      "5",
      "7",
    ]);

    expect(diff).toBeInstanceOf(IndexChange);
    expect((diff as IndexChange).newIndex).toBe(1);
    expect((diff as IndexChange).oldIndex).toBe(0);
  });

  it("Move 7 down to the top", () => {
    const diff = list2.getChange({ id: "7" }, [
      "7",
      "1",
      "2",
      "3",
      "4",
      "5",
      "6",
    ]);

    expect(diff).toBeInstanceOf(IndexChange);
    expect((diff as IndexChange).newIndex).toBe(0);
    expect((diff as IndexChange).oldIndex).toBe(2);
  });

  it("Move 5 to the top level", () => {
    const diff = list2.getChange({ id: "5" }, [
      "1",
      "5",
      "2",
      "3",
      "4",
      "6",
      "7",
    ]);

    expect(diff).toBeInstanceOf(LevelChange);
    expect((diff as LevelChange).parent).toBeUndefined();
  });

  it("Move 5 to the top level, begin of the list", () => {
    const diff = list2.getChange({ id: "5" }, [
      "5",
      "1",
      "2",
      "3",
      "4",
      "6",
      "7",
    ]);

    expect(diff).toBeInstanceOf(LevelChange);
    expect((diff as LevelChange).parent).toBeUndefined();
  });

  it("Move 6 one level up", () => {
    const diff = list2.getChange({ id: "6" }, [
      "1",
      "2",
      "6",
      "3",
      "4",
      "5",
      "7",
    ]);

    expect(diff).toBeInstanceOf(LevelChange);
    expect((diff as LevelChange).parent?.id).toBe("2");
  });

  it("Move a parent to the top", () => {
    const diff = list2.getChange({ id: "4" }, [
      "4",
      "5",
      "6",
      "1",
      "2",
      "3",
      "7",
    ]);

    expect(diff).toBeInstanceOf(LevelChange);
    expect((diff as LevelChange).parent?.id).toBeUndefined();
  });

  it("Move a parent same level", () => {
    const diff = list2.getChange({ id: "4" }, [
      "1",
      "2",
      "4",
      "5",
      "6",
      "3",
      "7",
    ]);

    expect(diff).toBeInstanceOf(IndexChange);
    expect((diff as IndexChange).newIndex).toBe(0);
  });

  it("Move 5 to the bottom", () => {
    const diff = list2.getChange({ id: "5" }, [
      "1",
      "2",
      "3",
      "4",
      "6",
      "7",
      "5",
    ]);

    expect(diff).toBeInstanceOf(LevelChange);
    expect((diff as LevelChange).parent).toBeUndefined();
  });

  it("Construct list", () => {
    //given
    const list = [
      { id: "0", level: 0, index: 0 },
      { id: "1", level: 1, index: 0 },
      { id: "2", level: 0, index: 1 },
      { id: "3", level: 1, index: 0 },
      { id: "4", level: 0, index: 2 },
      { id: "5", level: 1, index: 0 },
    ];

    //when
    const result = new ExecutionList(list);

    //then
    expect(result.expandableList).toEqual([
      {
        executionList: [{ id: "1", index: 0, level: 1 }],
        id: "0",
        index: 0,
        isCollapsed: false,
        level: 0,
      },
      {
        executionList: [{ id: "3", index: 0, level: 1 }],
        id: "2",
        index: 1,
        isCollapsed: false,
        level: 0,
      },
      {
        executionList: [{ id: "5", index: 0, level: 1 }],
        id: "4",
        index: 2,
        isCollapsed: false,
        level: 0,
      },
    ]);
  });
});
